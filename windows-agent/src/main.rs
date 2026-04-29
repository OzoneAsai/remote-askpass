#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::{
    collections::VecDeque,
    ffi::c_void,
    fs::{self, File, OpenOptions},
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Once},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use parking_lot::Mutex;
use rand::{distr::Alphanumeric, Rng};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{watch, Mutex as AsyncMutex},
};
use tracing::{error, info, warn};

const APP_NAME: &str = "RemoteAskpassBridge";
const DEFAULT_PORT: u16 = 17878;
const TRAY_STATUS_ID: &str = "status";
const TRAY_ENABLE_ID: &str = "enable";
const TRAY_DISABLE_ID: &str = "disable";
const TRAY_RECENT_ID: &str = "recent";
const TRAY_PAIRING_ENABLE_ID: &str = "pairing-enable";
const TRAY_PAIRING_DISABLE_ID: &str = "pairing-disable";
const TRAY_EXIT_ID: &str = "exit";
static RUSTLS_PROVIDER_INIT: Once = Once::new();

#[derive(Parser, Debug)]
#[command(author, version, about = "Windows agent for Remote Askpass Bridge")]
struct Cli {
    #[command(subcommand)]
    command: Option<CommandKind>,

    #[arg(long, env = "REMOTE_ASKPASS_AGENT_CONFIG")]
    config: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum CommandKind {
    Serve {
        #[arg(long)]
        listen: Option<SocketAddr>,

        #[arg(long, help = "Non-interactive prompt answer for tests only")]
        test_password: Option<String>,

        #[arg(
            long,
            help = "Use stderr/stdin console prompt instead of Windows dialog"
        )]
        console_prompt: bool,

        #[arg(long, help = "Do not create a Windows tray icon")]
        no_tray: bool,
    },
    SelfTest,
    WslSelfTest,
    WslSudoSelfTest,
    WslInstallHelper {
        #[arg(
            long,
            help = "WSL user to install for; defaults to WSL-account in .env"
        )]
        account: Option<String>,

        #[arg(long, help = "Agent URL to write into WSL config")]
        agent_url: Option<String>,
    },
    WslInstalledHelperSelfTest,
    RegisterStartup,
    UnregisterStartup,
    ShowConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct Config {
    listen_addr: SocketAddr,
    enabled: bool,
    dialog_timeout_seconds: u64,
    recent_request_limit: usize,
    startup_enabled: bool,
    tls_mode: TlsMode,
    allowed_hosts: Vec<String>,
    certificate_days: u32,
    linux_config_agent_url: String,
    openssl_path: String,
    server_hostname: String,
    server_cert_path: String,
    server_key_path: String,
    server_alt_names: Vec<String>,
    ca_cert_path: String,
    ca_key_path: String,
    ca_subject: String,
    client_cert_subject_prefix: String,
    #[serde(default)]
    pairing_window_seconds: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TlsMode {
    DisabledForLocalTesting,
    Mtls,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PORT),
            enabled: true,
            dialog_timeout_seconds: 30,
            recent_request_limit: 50,
            startup_enabled: false,
            tls_mode: TlsMode::DisabledForLocalTesting,
            allowed_hosts: Vec::new(),
            certificate_days: 825,
            linux_config_agent_url: format!("http://127.0.0.1:{DEFAULT_PORT}/ask"),
            openssl_path: "openssl".to_string(),
            server_hostname: "remote-askpass-agent.local".to_string(),
            server_cert_path: "certs/server.crt".to_string(),
            server_key_path: "certs/server.key".to_string(),
            server_alt_names: vec![
                "DNS:localhost".to_string(),
                "IP:127.0.0.1".to_string(),
                "DNS:remote-askpass-agent.local".to_string(),
            ],
            ca_cert_path: "certs/agent-ca.crt".to_string(),
            ca_key_path: "certs/agent-ca.key".to_string(),
            ca_subject: "/CN=Remote Askpass Bridge Local CA".to_string(),
            client_cert_subject_prefix: "/CN=remote-askpass-client-".to_string(),
            pairing_window_seconds: 0,
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Config,
    runtime: Arc<Mutex<RuntimeState>>,
    data_dir: PathBuf,
    prompt: Arc<dyn PromptProvider>,
    active_prompt: Arc<AsyncMutex<()>>,
    recent: Arc<Mutex<VecDeque<RecentRequest>>>,
}

impl AppState {
    fn is_enabled(&self) -> bool {
        self.runtime.lock().enabled
    }

    fn set_enabled(&self, enabled: bool) -> bool {
        let mut runtime = self.runtime.lock();
        runtime.enabled = enabled;
        runtime.enabled
    }

    fn open_pairing_window(&self) -> PairingWindow {
        let expires_at = if self.config.pairing_window_seconds == 0 {
            None
        } else {
            Some(Utc::now() + chrono::Duration::seconds(self.config.pairing_window_seconds as i64))
        };
        let window = PairingWindow {
            token: make_nonce(),
            opened_at: Utc::now(),
            expires_at,
        };
        self.runtime.lock().pairing = Some(window.clone());
        window
    }

    fn close_pairing_window(&self) -> bool {
        self.runtime.lock().pairing.take().is_some()
    }

    fn validate_pairing_token(&self, token: &str) -> bool {
        let mut runtime = self.runtime.lock();
        let Some(window) = &runtime.pairing else {
            return false;
        };
        if window.is_expired() {
            runtime.pairing = None;
            return false;
        }
        window.token == token
    }

    fn pairing_is_open(&self) -> bool {
        let mut runtime = self.runtime.lock();
        let Some(window) = &runtime.pairing else {
            return false;
        };
        if window.is_expired() {
            runtime.pairing = None;
            return false;
        }
        true
    }
}

#[derive(Debug)]
struct RuntimeState {
    enabled: bool,
    pairing: Option<PairingWindow>,
}

#[derive(Debug, Clone)]
struct PairingWindow {
    token: String,
    opened_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

impl PairingWindow {
    fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| Utc::now() > expires_at)
    }
}

#[derive(Debug, Clone, Serialize)]
struct RecentRequest {
    at: DateTime<Utc>,
    prompt: String,
    nonce: String,
    host: Option<String>,
    user: Option<String>,
    cwd: Option<String>,
    command: Option<String>,
    outcome: RequestOutcome,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum RequestOutcome {
    Approved,
    Denied,
    TimedOut,
    Rejected,
}

#[derive(Debug, Deserialize)]
struct AskQuery {
    prompt: Option<String>,
    nonce: Option<String>,
    host: Option<String>,
    user: Option<String>,
    cwd: Option<String>,
    command: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PairRequest {
    token: String,
    client_name: String,
    #[serde(default)]
    public_key_pem: Option<String>,
    #[serde(default)]
    csr_pem: Option<String>,
}

#[derive(Debug, Serialize)]
struct PairingWindowView {
    enabled: bool,
    token: String,
    opened_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    manual_close: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct PairingRecord {
    client_name: String,
    public_key_pem: Option<String>,
    csr_pem: Option<String>,
    issued_client_cert_path: Option<String>,
    paired_at: DateTime<Utc>,
    note: String,
}

#[derive(Debug, Serialize)]
struct PairResponse {
    record: PairingRecord,
    server_ca_pem: Option<String>,
    issued_client_cert_pem: Option<String>,
    linux_config: LinuxHelperConfig,
}

#[derive(Debug, Serialize)]
struct LinuxHelperConfig {
    agent_url: String,
    transport_mode: String,
    tls_mode: String,
    client_cert_path: String,
    client_key_path: String,
    server_ca_path: String,
    connect_timeout_seconds: u64,
    request_timeout_seconds: u64,
    send_host: bool,
    send_user: bool,
    send_cwd: bool,
    send_command_hint: bool,
}

#[derive(Debug)]
struct IssuedClientMaterial {
    client_cert_path: PathBuf,
    client_cert_pem: String,
    server_ca_pem: String,
}

struct SingleInstanceGuard {
    file: Option<File>,
    path: PathBuf,
}

#[derive(Debug, Serialize)]
struct StatusView {
    enabled: bool,
    listen_addr: SocketAddr,
    tls_mode: TlsMode,
    allowed_hosts: Vec<String>,
    recent_count: usize,
    pairing_open: bool,
}

#[derive(Debug, Serialize)]
struct ControlView {
    enabled: bool,
}

#[derive(Debug, Clone)]
struct PromptRequest {
    prompt: String,
    nonce: String,
    host: Option<String>,
    user: Option<String>,
    cwd: Option<String>,
    command: Option<String>,
    received_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PromptDecision {
    Approve(String),
    Deny,
    Timeout,
}

#[async_trait]
trait PromptProvider: Send + Sync {
    async fn ask(&self, request: PromptRequest, timeout: Duration) -> PromptDecision;
}

struct ConsolePromptProvider;

#[async_trait]
impl PromptProvider for ConsolePromptProvider {
    async fn ask(&self, request: PromptRequest, timeout: Duration) -> PromptDecision {
        let task = tokio::task::spawn_blocking(move || {
            eprintln!("Remote sudo request");
            eprintln!("  time: {}", request.received_at);
            eprintln!("  nonce: {}", request.nonce);
            eprintln!("  host: {}", request.host.as_deref().unwrap_or("(unknown)"));
            eprintln!("  user: {}", request.user.as_deref().unwrap_or("(unknown)"));
            eprintln!("  prompt: {}", request.prompt);
            if let Some(cwd) = &request.cwd {
                eprintln!("  cwd: {cwd}");
            }
            if let Some(command) = &request.command {
                eprintln!("  command: {command}");
            }
            match rpassword::prompt_password(
                "Approve by entering password, or leave empty to deny: ",
            ) {
                Ok(password) if !password.is_empty() => PromptDecision::Approve(password),
                Ok(_) => PromptDecision::Deny,
                Err(err) => {
                    warn!("prompt failed: {err}");
                    PromptDecision::Deny
                }
            }
        });

        match tokio::time::timeout(timeout, task).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(err)) => {
                warn!("prompt task failed: {err}");
                PromptDecision::Deny
            }
            Err(_) => PromptDecision::Timeout,
        }
    }
}

#[cfg(windows)]
struct WindowsDialogPromptProvider;

#[cfg(windows)]
#[async_trait]
impl PromptProvider for WindowsDialogPromptProvider {
    async fn ask(&self, request: PromptRequest, timeout: Duration) -> PromptDecision {
        let task =
            tokio::task::spawn_blocking(move || run_windows_prompt_dialog(&request, timeout));

        match task.await {
            Ok(Ok(decision)) => decision,
            Ok(Err(err)) => {
                warn!("dialog prompt failed: {err}");
                PromptDecision::Deny
            }
            Err(err) => {
                warn!("dialog prompt task failed: {err}");
                PromptDecision::Deny
            }
        }
    }
}

#[derive(Clone)]
struct FixedPromptProvider {
    password: String,
}

#[async_trait]
impl PromptProvider for FixedPromptProvider {
    async fn ask(&self, _request: PromptRequest, _timeout: Duration) -> PromptDecision {
        PromptDecision::Approve(self.password.clone())
    }
}

#[cfg(test)]
struct SlowPromptProvider;

#[cfg(test)]
#[async_trait]
impl PromptProvider for SlowPromptProvider {
    async fn ask(&self, _request: PromptRequest, _timeout: Duration) -> PromptDecision {
        tokio::time::sleep(Duration::from_secs(2)).await;
        PromptDecision::Approve("slow-secret".to_string())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_crypto_provider();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let config_path = resolve_config_path(cli.config.as_deref())?;

    match cli.command.unwrap_or(CommandKind::Serve {
        listen: None,
        test_password: None,
        console_prompt: false,
        no_tray: false,
    }) {
        CommandKind::Serve {
            listen,
            test_password,
            console_prompt,
            no_tray,
        } => {
            let mut config = load_or_create_config(&config_path)?;
            if let Some(addr) = listen {
                config.listen_addr = addr;
            }
            let data_dir = config_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            run_server(
                config,
                data_dir,
                provider_for_runtime(test_password, console_prompt),
                !no_tray,
            )
            .await
        }
        CommandKind::SelfTest => self_test().await,
        CommandKind::WslSelfTest => wsl_self_test().await,
        CommandKind::WslSudoSelfTest => wsl_sudo_self_test().await,
        CommandKind::WslInstallHelper { account, agent_url } => {
            wsl_install_helper(account.as_deref(), agent_url.as_deref())
        }
        CommandKind::WslInstalledHelperSelfTest => wsl_installed_helper_self_test().await,
        CommandKind::RegisterStartup => {
            register_startup()?;
            println!("registered startup entry");
            Ok(())
        }
        CommandKind::UnregisterStartup => {
            unregister_startup()?;
            println!("unregistered startup entry");
            Ok(())
        }
        CommandKind::ShowConfig => {
            let config = load_or_create_config(&config_path)?;
            println!("{}", serde_json::to_string_pretty(&config)?);
            Ok(())
        }
    }
}

fn install_rustls_crypto_provider() {
    RUSTLS_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn provider_for_runtime(
    test_password: Option<String>,
    console_prompt: bool,
) -> Arc<dyn PromptProvider> {
    if let Some(password) = test_password {
        return Arc::new(FixedPromptProvider { password });
    }

    if console_prompt {
        return Arc::new(ConsolePromptProvider);
    }

    #[cfg(windows)]
    {
        Arc::new(WindowsDialogPromptProvider)
    }

    #[cfg(not(windows))]
    {
        Arc::new(ConsolePromptProvider)
    }
}

async fn run_server(
    config: Config,
    data_dir: PathBuf,
    prompt: Arc<dyn PromptProvider>,
    with_tray: bool,
) -> Result<()> {
    let _instance = SingleInstanceGuard::acquire(&data_dir)?;
    let state = build_state(config.clone(), data_dir.clone(), prompt);
    let app = build_router(state.clone());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    if with_tray {
        spawn_tray(state.clone(), shutdown_tx.clone());
    }
    match config.tls_mode {
        TlsMode::DisabledForLocalTesting => {
            let listener = TcpListener::bind(config.listen_addr)
                .await
                .with_context(|| format!("failed to bind {}", config.listen_addr))?;
            let actual_addr = listener.local_addr()?;
            info!("Remote Askpass Agent listening on http://{actual_addr}");
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal(shutdown_rx))
                .await
                .context("server failed")
        }
        TlsMode::Mtls => {
            let tls_config = build_mtls_rustls_config(&config, &data_dir)?;
            let handle = Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal(shutdown_rx).await;
                shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
            });
            info!(
                "Remote Askpass Agent listening with mTLS on https://{}",
                config.listen_addr
            );
            axum_server::bind_rustls(config.listen_addr, tls_config)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .context("mTLS server failed")
        }
    }
}

fn build_state(config: Config, data_dir: PathBuf, prompt: Arc<dyn PromptProvider>) -> AppState {
    AppState {
        runtime: Arc::new(Mutex::new(RuntimeState {
            enabled: config.enabled,
            pairing: None,
        })),
        config,
        data_dir,
        prompt,
        active_prompt: Arc::new(AsyncMutex::new(())),
        recent: Arc::new(Mutex::new(VecDeque::new())),
    }
}

fn build_app(config: Config, data_dir: PathBuf, prompt: Arc<dyn PromptProvider>) -> Router {
    build_router(build_state(config, data_dir, prompt))
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/ask", get(ask))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/status", get(status))
        .route("/recent", get(recent))
        .route("/control/enable", post(control_enable))
        .route("/control/disable", post(control_disable))
        .route("/pairing/enable", post(pairing_enable))
        .route("/pairing/disable", post(pairing_disable))
        .route("/pair", post(pair))
        .with_state(state)
}

#[cfg(windows)]
fn spawn_tray(state: AppState, shutdown_tx: watch::Sender<bool>) {
    std::thread::spawn(move || {
        if let Err(err) = run_tray_thread(state, shutdown_tx) {
            warn!("tray thread failed: {err}");
        }
    });
}

#[cfg(not(windows))]
fn spawn_tray(_state: AppState, _shutdown_tx: watch::Sender<bool>) {}

#[cfg(windows)]
fn run_tray_thread(state: AppState, shutdown_tx: watch::Sender<bool>) -> Result<()> {
    use tray_icon::{
        menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
        TrayIconBuilder,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetMessageW, TranslateMessage, MSG,
    };

    let menu = Menu::new();
    let status_item = MenuItem::with_id(TRAY_STATUS_ID, tray_status_text(&state), false, None);
    let enable_item = MenuItem::with_id(TRAY_ENABLE_ID, "Enable Askpass", true, None);
    let disable_item = MenuItem::with_id(TRAY_DISABLE_ID, "Disable Askpass", true, None);
    let recent_item = MenuItem::with_id(TRAY_RECENT_ID, "Log Recent Requests", true, None);
    let pairing_enable_item =
        MenuItem::with_id(TRAY_PAIRING_ENABLE_ID, "Enable Pairing", true, None);
    let pairing_disable_item =
        MenuItem::with_id(TRAY_PAIRING_DISABLE_ID, "Disable Pairing", true, None);
    let exit_item = MenuItem::with_id(TRAY_EXIT_ID, "Exit", true, None);
    menu.append(&status_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&enable_item)?;
    menu.append(&disable_item)?;
    menu.append(&recent_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&pairing_enable_item)?;
    menu.append(&pairing_disable_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&exit_item)?;

    let icon = tray_icon_image(state.is_enabled())?;
    let _tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Remote Askpass Bridge")
        .with_icon(icon)
        .build()?;

    let handler_state = state.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        handle_tray_menu_event(event.id.as_ref(), &handler_state, &shutdown_tx);
    }));

    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn handle_tray_menu_event(id: &str, state: &AppState, shutdown_tx: &watch::Sender<bool>) {
    match id {
        TRAY_ENABLE_ID => {
            state.set_enabled(true);
            info!("askpass enabled from tray");
        }
        TRAY_DISABLE_ID => {
            state.set_enabled(false);
            info!("askpass disabled from tray");
        }
        TRAY_RECENT_ID => {
            log_recent_requests(state);
        }
        TRAY_PAIRING_ENABLE_ID => {
            let window = state.open_pairing_window();
            info!(
                "pairing enabled from tray; token={}, expires_at={:?}",
                window.token, window.expires_at
            );
        }
        TRAY_PAIRING_DISABLE_ID => {
            state.close_pairing_window();
            info!("pairing disabled from tray");
        }
        TRAY_STATUS_ID => {
            info!("{}", tray_status_text(state));
        }
        TRAY_EXIT_ID => {
            let _ = shutdown_tx.send(true);
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::PostQuitMessage(0);
            }
        }
        _ => {}
    }
}

fn tray_status_text(state: &AppState) -> String {
    format!(
        "Status: {}, pairing: {}, recent: {}",
        if state.is_enabled() {
            "enabled"
        } else {
            "disabled"
        },
        if state.pairing_is_open() {
            "open"
        } else {
            "closed"
        },
        state.recent.lock().len()
    )
}

fn log_recent_requests(state: &AppState) {
    let recent = state.recent.lock();
    if recent.is_empty() {
        info!("recent requests: none");
        return;
    }
    for request in recent.iter().take(10) {
        info!(
            "recent request: at={}, host={:?}, user={:?}, command={:?}, outcome={:?}",
            request.at, request.host, request.user, request.command, request.outcome
        );
    }
}

#[cfg(windows)]
fn tray_icon_image(enabled: bool) -> Result<tray_icon::Icon> {
    let mut rgba = vec![0u8; 16 * 16 * 4];
    let (r, g, b) = if enabled {
        (36, 164, 84)
    } else {
        (180, 55, 55)
    };
    for y in 0..16 {
        for x in 0..16 {
            let idx = (y * 16 + x) * 4;
            let edge = x == 0 || y == 0 || x == 15 || y == 15;
            rgba[idx] = if edge { 20 } else { r };
            rgba[idx + 1] = if edge { 20 } else { g };
            rgba[idx + 2] = if edge { 20 } else { b };
            rgba[idx + 3] = 255;
        }
    }
    tray_icon::Icon::from_rgba(rgba, 16, 16).context("failed to create tray icon")
}

async fn status(State(state): State<AppState>) -> Json<StatusView> {
    Json(StatusView {
        enabled: state.is_enabled(),
        listen_addr: state.config.listen_addr,
        tls_mode: state.config.tls_mode,
        allowed_hosts: state.config.allowed_hosts.clone(),
        recent_count: state.recent.lock().len(),
        pairing_open: state.pairing_is_open(),
    })
}

async fn recent(State(state): State<AppState>) -> Json<Vec<RecentRequest>> {
    Json(state.recent.lock().iter().cloned().collect())
}

async fn control_enable(State(state): State<AppState>) -> Json<ControlView> {
    Json(ControlView {
        enabled: state.set_enabled(true),
    })
}

async fn control_disable(State(state): State<AppState>) -> Json<ControlView> {
    Json(ControlView {
        enabled: state.set_enabled(false),
    })
}

async fn pairing_enable(State(state): State<AppState>) -> Json<PairingWindowView> {
    let window = state.open_pairing_window();
    Json(PairingWindowView {
        enabled: true,
        token: window.token,
        opened_at: window.opened_at,
        expires_at: window.expires_at,
        manual_close: window.expires_at.is_none(),
    })
}

async fn pairing_disable(State(state): State<AppState>) -> Json<PairingWindowView> {
    state.close_pairing_window();
    Json(PairingWindowView {
        enabled: false,
        token: String::new(),
        opened_at: Utc::now(),
        expires_at: None,
        manual_close: true,
    })
}

async fn pair(State(state): State<AppState>, Json(request): Json<PairRequest>) -> Response {
    if !state.validate_pairing_token(&request.token) {
        return (StatusCode::FORBIDDEN, "pairing window is not open\n").into_response();
    }
    if request.client_name.trim().is_empty()
        || request
            .public_key_pem
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
            && request
                .csr_pem
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            "missing client_name and public_key_pem/csr_pem\n",
        )
            .into_response();
    }

    let issue_result = match request.csr_pem.as_deref() {
        Some(csr_pem) if !csr_pem.trim().is_empty() => {
            match issue_client_certificate(
                &state.config,
                &state.data_dir,
                &request.client_name,
                csr_pem,
            ) {
                Ok(material) => Some(Ok(material)),
                Err(err) => Some(Err(err)),
            }
        }
        _ => None,
    };
    let issued_material = match issue_result {
        Some(Ok(material)) => Some(material),
        Some(Err(err)) => {
            error!("failed to issue client certificate: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to issue client certificate\n",
            )
                .into_response();
        }
        None => None,
    };

    let record = PairingRecord {
        client_name: request.client_name.clone(),
        public_key_pem: request.public_key_pem,
        csr_pem: request.csr_pem,
        issued_client_cert_path: issued_material
            .as_ref()
            .map(|material| material.client_cert_path.display().to_string()),
        paired_at: Utc::now(),
        note: if issued_material.is_some() {
            "Client certificate issued from local CA. Configure helper paths from linux_config."
                .to_string()
        } else {
            "Certificate issuance skipped; MVP pairing record saved because no csr_pem was supplied."
                .to_string()
        },
    };
    match save_pairing_record(&state.data_dir, &record) {
        Ok(()) => {
            let response = PairResponse {
                linux_config: linux_helper_config(&state.config),
                server_ca_pem: issued_material
                    .as_ref()
                    .map(|material| material.server_ca_pem.clone()),
                issued_client_cert_pem: issued_material
                    .as_ref()
                    .map(|material| material.client_cert_pem.clone()),
                record,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(err) => {
            error!("failed to save pairing record: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to save pairing record\n",
            )
                .into_response()
        }
    }
}

async fn ask(State(state): State<AppState>, Query(query): Query<AskQuery>) -> Response {
    if !state.is_enabled() {
        return (StatusCode::FORBIDDEN, "askpass disabled\n").into_response();
    }

    let Some(prompt) = query
        .prompt
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .cloned()
    else {
        return (StatusCode::BAD_REQUEST, "missing prompt\n").into_response();
    };

    if !host_is_allowed(&state.config.allowed_hosts, query.host.as_deref()) {
        record_recent(&state, &query, prompt, RequestOutcome::Rejected);
        return (StatusCode::FORBIDDEN, "host not allowed\n").into_response();
    }

    let Ok(_guard) = state.active_prompt.try_lock() else {
        return (StatusCode::CONFLICT, "already prompting\n").into_response();
    };

    let request = PromptRequest {
        prompt: prompt.clone(),
        nonce: query.nonce.clone().unwrap_or_else(make_nonce),
        host: query.host.clone(),
        user: query.user.clone(),
        cwd: query.cwd.clone(),
        command: query.command.clone(),
        received_at: Utc::now(),
    };

    let decision = state
        .prompt
        .ask(
            request,
            Duration::from_secs(state.config.dialog_timeout_seconds),
        )
        .await;

    match decision {
        PromptDecision::Approve(password) if !password.is_empty() => {
            record_recent(&state, &query, prompt, RequestOutcome::Approved);
            (StatusCode::OK, format!("{password}\n")).into_response()
        }
        PromptDecision::Approve(_) | PromptDecision::Deny => {
            record_recent(&state, &query, prompt, RequestOutcome::Denied);
            (StatusCode::FORBIDDEN, "denied\n").into_response()
        }
        PromptDecision::Timeout => {
            record_recent(&state, &query, prompt, RequestOutcome::TimedOut);
            (StatusCode::REQUEST_TIMEOUT, "timeout\n").into_response()
        }
    }
}

fn host_is_allowed(allowed_hosts: &[String], host: Option<&str>) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }
    let Some(host) = host.and_then(normalize_host_name) else {
        return false;
    };
    allowed_hosts
        .iter()
        .filter_map(|allowed| normalize_host_name(allowed))
        .any(|allowed| allowed == host)
}

fn normalize_host_name(host: &str) -> Option<String> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

fn record_recent(state: &AppState, query: &AskQuery, prompt: String, outcome: RequestOutcome) {
    let mut recent = state.recent.lock();
    recent.push_front(RecentRequest {
        at: Utc::now(),
        prompt,
        nonce: query.nonce.clone().unwrap_or_default(),
        host: query.host.clone(),
        user: query.user.clone(),
        cwd: query.cwd.clone(),
        command: query.command.clone(),
        outcome,
    });
    while recent.len() > state.config.recent_request_limit {
        recent.pop_back();
    }
}

fn save_pairing_record(data_dir: &Path, record: &PairingRecord) -> Result<()> {
    let pairings_dir = data_dir.join("pairings");
    fs::create_dir_all(&pairings_dir)
        .with_context(|| format!("failed to create {}", pairings_dir.display()))?;
    let path = pairings_dir.join(format!("{}.json", safe_file_stem(&record.client_name)));
    fs::write(&path, serde_json::to_string_pretty(record)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn build_mtls_rustls_config(config: &Config, data_dir: &Path) -> Result<RustlsConfig> {
    install_rustls_crypto_provider();
    ensure_ca_material(config, data_dir)?;
    ensure_server_certificate(config, data_dir)?;

    let server_cert_path = resolve_data_path(data_dir, &config.server_cert_path);
    let server_key_path = resolve_data_path(data_dir, &config.server_key_path);
    let ca_cert_path = resolve_data_path(data_dir, &config.ca_cert_path);

    let server_certs = load_certificates(&server_cert_path)?;
    let server_key = load_private_key(&server_key_path)?;
    let mut client_roots = RootCertStore::empty();
    for cert in load_certificates(&ca_cert_path)? {
        client_roots
            .add(cert)
            .with_context(|| format!("failed to add CA cert {}", ca_cert_path.display()))?;
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .context("failed to build client certificate verifier")?;
    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .context("failed to build mTLS server config")?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("failed to parse certificates from {}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .with_context(|| format!("failed to parse private key from {}", path.display()))?
        .ok_or_else(|| anyhow!("private key not found in {}", path.display()))
}

fn issue_client_certificate(
    config: &Config,
    data_dir: &Path,
    client_name: &str,
    csr_pem: &str,
) -> Result<IssuedClientMaterial> {
    ensure_ca_material(config, data_dir)?;
    ensure_server_certificate(config, data_dir)?;

    let pairings_dir = data_dir.join("pairings");
    fs::create_dir_all(&pairings_dir)
        .with_context(|| format!("failed to create {}", pairings_dir.display()))?;
    let stem = safe_file_stem(client_name);
    let csr_path = pairings_dir.join(format!("{stem}.csr"));
    let client_cert_path = pairings_dir.join(format!("{stem}.crt"));
    fs::write(&csr_path, csr_pem)
        .with_context(|| format!("failed to write {}", csr_path.display()))?;
    let client_ext_path = pairings_dir.join(format!("{stem}.ext"));
    fs::write(
        &client_ext_path,
        "[v3_client]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = clientAuth\n",
    )
    .with_context(|| format!("failed to write {}", client_ext_path.display()))?;

    run_command(
        &config.openssl_path,
        &[
            "x509",
            "-req",
            "-in",
            &path_arg(&csr_path),
            "-CA",
            &path_arg(&resolve_data_path(data_dir, &config.ca_cert_path)),
            "-CAkey",
            &path_arg(&resolve_data_path(data_dir, &config.ca_key_path)),
            "-CAcreateserial",
            "-out",
            &path_arg(&client_cert_path),
            "-days",
            &config.certificate_days.to_string(),
            "-sha256",
            "-extfile",
            &path_arg(&client_ext_path),
            "-extensions",
            "v3_client",
        ],
    )
    .context("failed to sign client CSR")?;

    Ok(IssuedClientMaterial {
        client_cert_pem: fs::read_to_string(&client_cert_path)
            .with_context(|| format!("failed to read {}", client_cert_path.display()))?,
        server_ca_pem: fs::read_to_string(resolve_data_path(data_dir, &config.ca_cert_path))
            .context("failed to read CA certificate")?,
        client_cert_path,
    })
}

fn ensure_ca_material(config: &Config, data_dir: &Path) -> Result<()> {
    let openssl_config_path = ensure_openssl_config(data_dir)?;
    let ca_cert_path = resolve_data_path(data_dir, &config.ca_cert_path);
    let ca_key_path = resolve_data_path(data_dir, &config.ca_key_path);
    if ca_cert_path.exists() && ca_key_path.exists() {
        return Ok(());
    }
    if let Some(parent) = ca_cert_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    run_command(
        &config.openssl_path,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-keyout",
            &path_arg(&ca_key_path),
            "-out",
            &path_arg(&ca_cert_path),
            "-days",
            &config.certificate_days.to_string(),
            "-sha256",
            "-config",
            &path_arg(&openssl_config_path),
            "-extensions",
            "v3_ca",
            "-subj",
            &config.ca_subject,
        ],
    )
    .context("failed to create local CA material")
}

fn ensure_server_certificate(config: &Config, data_dir: &Path) -> Result<()> {
    let openssl_config_path = ensure_openssl_config(data_dir)?;
    let server_cert_path = resolve_data_path(data_dir, &config.server_cert_path);
    let server_key_path = resolve_data_path(data_dir, &config.server_key_path);
    if server_cert_path.exists() && server_key_path.exists() {
        return Ok(());
    }
    if let Some(parent) = server_cert_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let csr_path = server_cert_path.with_extension("csr");
    let ext_path = server_cert_path.with_extension("ext");
    fs::write(
        &ext_path,
        format!(
            "[v3_server]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = {}\n",
            config.server_alt_names.join(",")
        ),
    )
    .with_context(|| format!("failed to write {}", ext_path.display()))?;
    run_command(
        &config.openssl_path,
        &[
            "req",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-keyout",
            &path_arg(&server_key_path),
            "-out",
            &path_arg(&csr_path),
            "-config",
            &path_arg(&openssl_config_path),
            "-subj",
            &format!("/CN={}", config.server_hostname),
        ],
    )
    .context("failed to create server CSR")?;
    run_command(
        &config.openssl_path,
        &[
            "x509",
            "-req",
            "-in",
            &path_arg(&csr_path),
            "-CA",
            &path_arg(&resolve_data_path(data_dir, &config.ca_cert_path)),
            "-CAkey",
            &path_arg(&resolve_data_path(data_dir, &config.ca_key_path)),
            "-CAcreateserial",
            "-out",
            &path_arg(&server_cert_path),
            "-days",
            &config.certificate_days.to_string(),
            "-sha256",
            "-extfile",
            &path_arg(&ext_path),
            "-extensions",
            "v3_server",
        ],
    )
    .context("failed to sign server certificate")
}

fn linux_helper_config(config: &Config) -> LinuxHelperConfig {
    LinuxHelperConfig {
        agent_url: config.linux_config_agent_url.clone(),
        transport_mode: "tailscale".to_string(),
        tls_mode: match config.tls_mode {
            TlsMode::DisabledForLocalTesting => "disabled_for_local_testing",
            TlsMode::Mtls => "mtls",
        }
        .to_string(),
        client_cert_path: "~/.config/remote-askpass/client.crt".to_string(),
        client_key_path: "~/.config/remote-askpass/client.key".to_string(),
        server_ca_path: "~/.config/remote-askpass/server-ca.crt".to_string(),
        connect_timeout_seconds: 3,
        request_timeout_seconds: 35,
        send_host: true,
        send_user: true,
        send_cwd: true,
        send_command_hint: false,
    }
}

fn ensure_openssl_config(data_dir: &Path) -> Result<PathBuf> {
    let path = data_dir.join("openssl.cnf");
    if path.exists() {
        return Ok(path);
    }
    fs::write(
        &path,
        r#"[req]
distinguished_name = dn
prompt = no

[dn]
CN = remote-askpass

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
"#,
    )
    .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn resolve_data_path(data_dir: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        data_dir.join(path)
    }
}

fn path_arg(path: &Path) -> String {
    path.display().to_string()
}

fn run_command(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to start {program}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("{program} failed: {stderr}"));
    }
    Ok(())
}

fn safe_file_stem(value: &str) -> String {
    let stem: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if stem.is_empty() {
        "client".to_string()
    } else {
        stem
    }
}

impl SingleInstanceGuard {
    fn acquire(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir)
            .with_context(|| format!("failed to create {}", data_dir.display()))?;
        let lock_path = data_dir.join("agent.lock");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .with_context(|| {
                format!(
                    "another Remote Askpass Agent appears to be running; lock exists at {}",
                    lock_path.display()
                )
            })?;
        Ok(Self {
            file: Some(file),
            path: lock_path,
        })
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Err(err) = fs::remove_file(&self.path) {
            warn!("failed to remove lock file {}: {err}", self.path.display());
        }
    }
}

async fn self_test() -> Result<()> {
    let config = Config {
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        dialog_timeout_seconds: 1,
        ..Config::default()
    };
    let listener = TcpListener::bind(config.listen_addr).await?;
    let addr = listener.local_addr()?;
    let app = build_app(
        config,
        std::env::temp_dir().join("remote-askpass-self-test"),
        Arc::new(FixedPromptProvider {
            password: "self-test-password".to_string(),
        }),
    );

    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let client = reqwest::Client::new();
    let prompt = urlencoding::encode("sudo password:");
    let url = format!("http://{addr}/ask?prompt={prompt}&nonce=selftest&host=self&user=tester");
    let response = client.get(url).send().await?;
    let status = response.status();
    let body = response.text().await?;
    if status != StatusCode::OK || body != "self-test-password\n" {
        server.abort();
        return Err(anyhow!(
            "self-test ask failed: status={status}, body={body:?}"
        ));
    }

    let missing_prompt = client
        .get(format!("http://{addr}/ask"))
        .send()
        .await?
        .status();
    server.abort();
    if missing_prompt != StatusCode::BAD_REQUEST {
        return Err(anyhow!(
            "self-test missing prompt failed: status={missing_prompt}"
        ));
    }

    println!("self-test passed");
    Ok(())
}

async fn wsl_self_test() -> Result<()> {
    let gateway = wsl_gateway().context("failed to resolve WSL gateway")?;
    let config = Config {
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        dialog_timeout_seconds: 1,
        ..Config::default()
    };
    let listener = TcpListener::bind(config.listen_addr).await?;
    let addr = listener.local_addr()?;
    let app = build_app(
        config,
        std::env::temp_dir().join("remote-askpass-wsl-self-test"),
        Arc::new(FixedPromptProvider {
            password: "wsl-self-test-password".to_string(),
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let url = format!(
        "http://{gateway}:{}/ask?prompt=sudo%20password%3A&nonce=wsl-selftest&host=wsl",
        addr.port()
    );
    let output = Command::new("wsl.exe")
        .args(["--exec", "curl", "--silent", "--show-error", "--fail", &url])
        .output()
        .context("failed to run wsl.exe curl")?;
    server.abort();

    if !output.status.success() {
        return Err(anyhow!(
            "WSL curl failed: status={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let body = String::from_utf8_lossy(&output.stdout);
    if body != "wsl-self-test-password\n" {
        return Err(anyhow!("unexpected WSL response body: {body:?}"));
    }
    println!("wsl-self-test passed via {url}");
    Ok(())
}

async fn wsl_sudo_self_test() -> Result<()> {
    let env_path = PathBuf::from(".env");
    let wsl_account =
        read_dotenv_value(&env_path, "WSL-account").context("WSL-account is missing from .env")?;
    let wsl_password = read_dotenv_value(&env_path, "WSL-Password")
        .context("WSL-Password is missing from .env")?;
    if wsl_password.is_empty() {
        return Err(anyhow!("WSL-Password is empty"));
    }

    let gateway = wsl_gateway().context("failed to resolve WSL gateway")?;
    let config = Config {
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        dialog_timeout_seconds: 1,
        ..Config::default()
    };
    let listener = TcpListener::bind(config.listen_addr).await?;
    let addr = listener.local_addr()?;
    let state = build_state(
        config,
        std::env::temp_dir().join("remote-askpass-wsl-sudo-self-test"),
        Arc::new(FixedPromptProvider {
            password: wsl_password,
        }),
    );
    let app = build_router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let url = format!("http://{gateway}:{}/ask", addr.port());
    let temp_name = format!("/tmp/remote-askpass-{}", make_nonce());
    let config_path = format!("{temp_name}/config.json");
    let helper_path = format!("{temp_name}/remote-askpass");
    let helper_source =
        windows_path_to_wsl(&std::env::current_dir()?.join("linux-helper/remote-askpass"))
            .context("failed to resolve linux-helper/remote-askpass for WSL")?;
    let script = format!(
        r#"
set -eu
rm -rf {temp_dir}
mkdir -p {temp_dir}
cleanup() {{ rm -rf {temp_dir}; }}
trap cleanup EXIT
cp {helper_source} {helper_path}
chmod 700 {helper_path}
cat > {config_path} <<'JSON'
{{
  "agent_url": {url_json},
  "transport_mode": "wsl-local",
  "tls_mode": "disabled_for_local_testing",
  "client_cert_path": "",
  "client_key_path": "",
  "server_ca_path": "",
  "connect_timeout_seconds": 3,
  "request_timeout_seconds": 35,
  "send_host": true,
  "send_user": true,
  "send_cwd": true,
  "send_command_hint": true
}}
JSON
chmod 600 {config_path}
REMOTE_ASKPASS_CONFIG={config_path} \
REMOTE_ASKPASS_COMMAND_HINT='wsl-sudo-self-test true' \
SUDO_ASKPASS={helper_path} \
sudo -A -k true
"#,
        temp_dir = shell_quote_arg(&temp_name),
        config_path = shell_quote_arg(&config_path),
        helper_path = shell_quote_arg(&helper_path),
        helper_source = shell_quote_arg(&helper_source),
        url_json = serde_json::to_string(&url)?,
    );
    let output = run_wsl_shell(Some(&wsl_account), &script)
        .context("failed to run WSL sudo askpass test")?;
    server.abort();

    if !output.status.success() {
        return Err(anyhow!(
            "WSL sudo askpass failed: status={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if state.recent.lock().is_empty() {
        return Err(anyhow!(
            "WSL sudo completed, but sudo did not call the askpass helper"
        ));
    }
    println!("wsl-sudo-self-test passed via {url}");
    Ok(())
}

async fn wsl_installed_helper_self_test() -> Result<()> {
    let env_path = PathBuf::from(".env");
    let wsl_account =
        read_dotenv_value(&env_path, "WSL-account").context("WSL-account is missing from .env")?;
    let wsl_password = read_dotenv_value(&env_path, "WSL-Password")
        .context("WSL-Password is missing from .env")?;
    if wsl_password.is_empty() {
        return Err(anyhow!("WSL-Password is empty"));
    }

    let config = Config {
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_PORT),
        dialog_timeout_seconds: 1,
        ..Config::default()
    };
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_addr))?;
    let state = build_state(
        config,
        std::env::temp_dir().join("remote-askpass-wsl-installed-helper-self-test"),
        Arc::new(FixedPromptProvider {
            password: wsl_password,
        }),
    );
    let app = build_router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let script = r#"
set -eu
test -x "$HOME/.local/bin/remote-askpass"
test -x "$HOME/.local/bin/rsudo"
test -f "$HOME/.config/remote-askpass/config.json"
sudo -k
PATH="$HOME/.local/bin:$PATH" rsudo true
"#;
    let output = run_wsl_shell(Some(&wsl_account), script)
        .context("failed to run installed WSL helper test")?;
    server.abort();

    if !output.status.success() {
        return Err(anyhow!(
            "installed WSL helper test failed: status={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if state.recent.lock().is_empty() {
        return Err(anyhow!(
            "installed WSL helper test completed, but the agent did not receive an ask request"
        ));
    }
    println!("wsl-installed-helper-self-test passed on 0.0.0.0:{DEFAULT_PORT}");
    Ok(())
}

fn wsl_install_helper(account: Option<&str>, agent_url: Option<&str>) -> Result<()> {
    let account = match account {
        Some(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => read_dotenv_value(Path::new(".env"), "WSL-account").ok(),
    };
    let helper_source =
        windows_path_to_wsl(&std::env::current_dir()?.join("linux-helper/remote-askpass"))
            .context("failed to resolve linux-helper/remote-askpass for WSL")?;
    let rsudo_source = windows_path_to_wsl(&std::env::current_dir()?.join("linux-helper/rsudo"))
        .context("failed to resolve linux-helper/rsudo for WSL")?;
    let agent_url = match agent_url {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => format!("http://{}:{DEFAULT_PORT}/ask", wsl_gateway()?),
    };
    let script = format!(
        r#"
set -eu
timestamp="$(date +%Y%m%d%H%M%S)"
bin_dir="$HOME/.local/bin"
cfg_dir="$HOME/.config/remote-askpass"
mkdir -p "$bin_dir" "$cfg_dir"
chmod 700 "$bin_dir" "$cfg_dir"
backup_if_exists() {{
  if [ -e "$1" ]; then
    cp "$1" "$1.bak.$timestamp"
  fi
}}
backup_if_exists "$bin_dir/remote-askpass"
backup_if_exists "$bin_dir/rsudo"
backup_if_exists "$cfg_dir/config.json"
cp {helper_source} "$bin_dir/remote-askpass"
cp {rsudo_source} "$bin_dir/rsudo"
chmod 700 "$bin_dir/remote-askpass" "$bin_dir/rsudo"
cat > "$cfg_dir/config.json" <<'JSON'
{{
  "agent_url": {agent_url_json},
  "transport_mode": "wsl-local",
  "tls_mode": "disabled_for_local_testing",
  "client_cert_path": "",
  "client_key_path": "",
  "server_ca_path": "",
  "connect_timeout_seconds": 3,
  "request_timeout_seconds": 35,
  "send_host": true,
  "send_user": true,
  "send_cwd": true,
  "send_command_hint": true
}}
JSON
chmod 600 "$cfg_dir/config.json"
printf '%s\n' "$bin_dir/remote-askpass"
printf '%s\n' "$bin_dir/rsudo"
printf '%s\n' "$cfg_dir/config.json"
"#,
        helper_source = shell_quote_arg(&helper_source),
        rsudo_source = shell_quote_arg(&rsudo_source),
        agent_url_json = serde_json::to_string(&agent_url)?,
    );
    let output =
        run_wsl_shell(account.as_deref(), &script).context("failed to install WSL helper")?;
    if !output.status.success() {
        return Err(anyhow!(
            "WSL helper install failed: status={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    println!(
        "installed WSL helper for account {}",
        account.as_deref().unwrap_or("(default)")
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    println!("agent_url={agent_url}");
    println!("run the Windows agent with: cargo run -p remote-askpass-windows-agent -- serve --listen 0.0.0.0:{DEFAULT_PORT}");
    Ok(())
}

fn windows_path_to_wsl(path: &Path) -> Result<String> {
    let output = Command::new("wsl.exe")
        .args(["--exec", "wslpath", "-a", &path_arg(path)])
        .output()
        .context("failed to run wslpath")?;
    if !output.status.success() {
        return Err(anyhow!(
            "wslpath failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return Err(anyhow!("wslpath returned an empty path"));
    }
    Ok(path)
}

fn run_wsl_shell(account: Option<&str>, script: &str) -> Result<std::process::Output> {
    let mut command = Command::new("wsl.exe");
    if let Some(account) = account.filter(|value| !value.trim().is_empty()) {
        command.args(["-u", account]);
    }
    command
        .args(["--exec", "sh", "-c", script])
        .output()
        .context("failed to run wsl.exe")
}

fn wsl_gateway() -> Result<String> {
    let output = Command::new("wsl.exe")
        .args(["--exec", "ip", "route", "show", "default"])
        .output()
        .context("failed to query WSL default gateway")?;
    if !output.status.success() {
        return Err(anyhow!(
            "WSL gateway query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let routes = String::from_utf8_lossy(&output.stdout);
    for line in routes.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.first() == Some(&"default") {
            if let Some(gateway) = parts
                .windows(2)
                .find_map(|pair| (pair[0] == "via").then_some(pair[1]))
            {
                return Ok(gateway.to_string());
            }
        }
    }
    Err(anyhow!("WSL default gateway is empty"))
}

fn shell_single_quote(value: &str) -> String {
    value.replace('\'', "'\"'\"'")
}

fn shell_quote_arg(value: &str) -> String {
    format!("'{}'", shell_single_quote(value))
}

fn read_dotenv_value(path: &Path, key: &str) -> Result<String> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((line_key, value)) = line.split_once('=') else {
            continue;
        };
        if line_key.trim() == key {
            return Ok(unquote_dotenv_value(value.trim()));
        }
    }
    Err(anyhow!("{key} not found in {}", path.display()))
}

fn unquote_dotenv_value(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

fn load_or_create_config(path: &Path) -> Result<Config> {
    if path.exists() {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        return serde_json::from_str(&text)
            .with_context(|| format!("failed to parse config {}", path.display()));
    }

    let config = Config::default();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config dir {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_string_pretty(&config)?)
        .with_context(|| format!("failed to write config {}", path.display()))?;
    Ok(config)
}

fn resolve_config_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }

    let appdata = std::env::var_os("APPDATA").ok_or_else(|| anyhow!("APPDATA is not set"))?;
    Ok(PathBuf::from(appdata).join(APP_NAME).join("config.json"))
}

fn startup_dir() -> Result<PathBuf> {
    let appdata = std::env::var_os("APPDATA").ok_or_else(|| anyhow!("APPDATA is not set"))?;
    Ok(PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup"))
}

fn startup_script_path() -> Result<PathBuf> {
    Ok(startup_dir()?.join("Remote Askpass Bridge.cmd"))
}

fn legacy_startup_shortcut_path() -> Result<PathBuf> {
    Ok(startup_dir()?.join("Remote Askpass Bridge.lnk"))
}

fn register_startup() -> Result<()> {
    let shortcut = startup_script_path()?;
    let exe = std::env::current_exe().context("failed to resolve current exe")?;
    let content = format!(
        "@echo off\r\ncd /d \"{}\"\r\n\"{}\" serve\r\n",
        exe.parent().unwrap_or_else(|| Path::new(".")).display(),
        exe.display(),
    );
    fs::write(&shortcut, content).with_context(|| format!("failed to write {}", shortcut.display()))
}

fn unregister_startup() -> Result<()> {
    for path in [startup_script_path()?, legacy_startup_shortcut_path()?] {
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }
    Ok(())
}

#[cfg(windows)]
#[repr(C)]
struct CredUiInfoW {
    cb_size: u32,
    hwnd_parent: *mut c_void,
    psz_message_text: *const u16,
    psz_caption_text: *const u16,
    hbm_banner: *mut c_void,
}

#[cfg(windows)]
const CREDUIWIN_GENERIC: u32 = 0x0000_0001;

#[cfg(windows)]
const ERROR_CANCELLED: u32 = 1223;

#[cfg(windows)]
#[link(name = "Credui")]
extern "system" {
    fn CredUIPromptForWindowsCredentialsW(
        pui: *mut CredUiInfoW,
        dw_auth_error: u32,
        pul_auth_package: *mut u32,
        pv_in_auth_buffer: *const c_void,
        ul_in_auth_buffer_size: u32,
        ppv_out_auth_buffer: *mut *mut c_void,
        pul_out_auth_buffer_size: *mut u32,
        pf_save: *mut i32,
        dw_flags: u32,
    ) -> u32;

    fn CredUnPackAuthenticationBufferW(
        dw_flags: u32,
        p_auth_buffer: *const c_void,
        cb_auth_buffer: u32,
        psz_user_name: *mut u16,
        pcch_max_user_name: *mut u32,
        psz_domain_name: *mut u16,
        pcch_max_domain_name: *mut u32,
        psz_password: *mut u16,
        pcch_max_password: *mut u32,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "Ole32")]
extern "system" {
    fn CoTaskMemFree(pv: *mut c_void);
}

#[cfg(windows)]
fn run_windows_prompt_dialog(request: &PromptRequest, timeout: Duration) -> Result<PromptDecision> {
    let _timeout = timeout;
    let detail = format!(
        "Time: {}\r\nHost: {}\r\nUser: {}\r\nPrompt: {}\r\nCwd: {}\r\nCommand: {}\r\nNonce: {}",
        request.received_at,
        request.host.as_deref().unwrap_or("(unknown)"),
        request.user.as_deref().unwrap_or("(unknown)"),
        request.prompt,
        request.cwd.as_deref().unwrap_or("(unknown)"),
        request.command.as_deref().unwrap_or("(none)"),
        request.nonce,
    );
    let caption = to_wide("Remote sudo request");
    let message = to_wide(&detail);
    let mut ui = CredUiInfoW {
        cb_size: std::mem::size_of::<CredUiInfoW>() as u32,
        hwnd_parent: std::ptr::null_mut(),
        psz_message_text: message.as_ptr(),
        psz_caption_text: caption.as_ptr(),
        hbm_banner: std::ptr::null_mut(),
    };
    let mut auth_package = 0u32;
    let mut out_auth_buffer: *mut c_void = std::ptr::null_mut();
    let mut out_auth_buffer_size = 0u32;
    let mut save = 0i32;

    let result = unsafe {
        CredUIPromptForWindowsCredentialsW(
            &mut ui,
            0,
            &mut auth_package,
            std::ptr::null(),
            0,
            &mut out_auth_buffer,
            &mut out_auth_buffer_size,
            &mut save,
            CREDUIWIN_GENERIC,
        )
    };

    if result == ERROR_CANCELLED {
        return Ok(PromptDecision::Deny);
    }
    if result != 0 {
        return Err(anyhow!(
            "CredUIPromptForWindowsCredentialsW failed: {result}"
        ));
    }

    let unpacked = unsafe { unpack_credential_password(out_auth_buffer, out_auth_buffer_size) };
    unsafe {
        CoTaskMemFree(out_auth_buffer);
    }
    let password = unpacked?;
    if password.is_empty() {
        Ok(PromptDecision::Deny)
    } else {
        Ok(PromptDecision::Approve(password))
    }
}

#[cfg(windows)]
unsafe fn unpack_credential_password(
    out_auth_buffer: *mut c_void,
    out_auth_buffer_size: u32,
) -> Result<String> {
    let mut username = vec![0u16; 512];
    let mut domain = vec![0u16; 512];
    let mut password = vec![0u16; 512];
    let mut username_len = username.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut password_len = password.len() as u32;

    let ok = CredUnPackAuthenticationBufferW(
        0,
        out_auth_buffer,
        out_auth_buffer_size,
        username.as_mut_ptr(),
        &mut username_len,
        domain.as_mut_ptr(),
        &mut domain_len,
        password.as_mut_ptr(),
        &mut password_len,
    );
    if ok == 0 {
        return Err(anyhow!("CredUnPackAuthenticationBufferW failed"));
    }

    Ok(String::from_utf16_lossy(&password[..password_len as usize]))
}

#[cfg(windows)]
fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn make_nonce() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

async fn shutdown_signal(mut tray_shutdown: watch::Receiver<bool>) {
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(err) = result {
                error!("failed to listen for shutdown signal: {err}");
            }
        }
        result = tray_shutdown.changed() => {
            if let Err(err) = result {
                warn!("tray shutdown sender dropped: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use std::process::Command as StdCommand;
    use tower::ServiceExt;

    fn test_data_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("remote-askpass-agent-test-{name}-{}", make_nonce()))
    }

    #[tokio::test]
    async fn ask_returns_only_password_on_stdout_body() {
        let app = build_app(
            Config::default(),
            test_data_dir("password-body"),
            Arc::new(FixedPromptProvider {
                password: "secret".to_string(),
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ask?prompt=sudo%20password%3A&nonce=n")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"secret\n");
    }

    #[tokio::test]
    async fn ask_rejects_missing_prompt() {
        let app = build_app(
            Config::default(),
            test_data_dir("missing-prompt"),
            Arc::new(FixedPromptProvider {
                password: "secret".to_string(),
            }),
        );

        let response = app
            .oneshot(Request::builder().uri("/ask").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ask_honors_enabled_flag() {
        let mut config = Config::default();
        config.enabled = false;
        let app = build_app(
            config,
            test_data_dir("disabled"),
            Arc::new(FixedPromptProvider {
                password: "secret".to_string(),
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ask?prompt=sudo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ask_rejects_missing_host_when_allowlist_is_configured() {
        let mut config = Config::default();
        config.allowed_hosts = vec!["pi-one".to_string()];
        let app = build_app(
            config,
            test_data_dir("allowlist-missing-host"),
            Arc::new(FixedPromptProvider {
                password: "secret".to_string(),
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ask?prompt=sudo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ask_allows_normalized_allowlisted_host() {
        let mut config = Config::default();
        config.allowed_hosts = vec!["PI-One.".to_string()];
        let app = build_app(
            config,
            test_data_dir("allowlist-normalized-host"),
            Arc::new(FixedPromptProvider {
                password: "secret".to_string(),
            }),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ask?prompt=sudo&host=pi-one")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn control_disable_rejects_future_asks() {
        let app = build_app(
            Config::default(),
            test_data_dir("control-disable"),
            Arc::new(FixedPromptProvider {
                password: "secret".to_string(),
            }),
        );

        let disable_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/control/disable")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disable_response.status(), StatusCode::OK);

        let ask_response = app
            .oneshot(
                Request::builder()
                    .uri("/ask?prompt=sudo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(ask_response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn recent_records_metadata_without_password() {
        let app = build_app(
            Config::default(),
            test_data_dir("recent"),
            Arc::new(FixedPromptProvider {
                password: "secret".to_string(),
            }),
        );

        let ask_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ask?prompt=sudo&nonce=n&host=h&user=u&command=whoami")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ask_response.status(), StatusCode::OK);

        let recent_response = app
            .oneshot(
                Request::builder()
                    .uri("/recent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recent_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(recent_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("\"nonce\":\"n\""));
        assert!(body.contains("\"outcome\":\"approved\""));
        assert!(!body.contains("secret"));
    }

    #[tokio::test]
    async fn concurrent_ask_is_rejected() {
        let app = build_app(
            Config::default(),
            test_data_dir("concurrent"),
            Arc::new(SlowPromptProvider),
        );

        let first = app.clone().oneshot(
            Request::builder()
                .uri("/ask?prompt=first")
                .body(Body::empty())
                .unwrap(),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = app.oneshot(
            Request::builder()
                .uri("/ask?prompt=second")
                .body(Body::empty())
                .unwrap(),
        );

        let (first_response, second_response) = tokio::join!(first, second);
        assert_eq!(first_response.unwrap().status(), StatusCode::OK);
        assert_eq!(second_response.unwrap().status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn pairing_window_accepts_client_record() {
        let data_dir = test_data_dir("pairing");
        let app = build_app(
            Config::default(),
            data_dir.clone(),
            Arc::new(FixedPromptProvider {
                password: "secret".to_string(),
            }),
        );

        let enable_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/pairing/enable")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enable_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(enable_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = body["token"].as_str().unwrap();

        let pair_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/pair")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"token":"{token}","client_name":"pi-1","public_key_pem":"PUBLIC KEY"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(pair_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(pair_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("\"client_name\":\"pi-1\""));
        assert!(body.contains("Certificate issuance skipped"));
        assert!(data_dir.join("pairings").join("pi-1.json").exists());
    }

    #[tokio::test]
    async fn pairing_with_csr_issues_client_certificate() {
        if StdCommand::new("openssl").arg("version").output().is_err() {
            eprintln!("skipping CSR issuance test because openssl is not available");
            return;
        }

        let data_dir = test_data_dir("pairing-csr");
        fs::create_dir_all(&data_dir).unwrap();
        let openssl_config_path = ensure_openssl_config(&data_dir).unwrap();
        let key_path = data_dir.join("client.key");
        let csr_path = data_dir.join("client.csr");
        let output = StdCommand::new("openssl")
            .args([
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &path_arg(&key_path),
                "-out",
                &path_arg(&csr_path),
                "-config",
                &path_arg(&openssl_config_path),
                "-subj",
                "/CN=pi-csr",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "openssl CSR generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let csr_pem = fs::read_to_string(&csr_path).unwrap();
        let app = build_app(
            Config::default(),
            data_dir.clone(),
            Arc::new(FixedPromptProvider {
                password: "secret".to_string(),
            }),
        );

        let enable_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/pairing/enable")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enable_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(enable_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = body["token"].as_str().unwrap();

        let pair_body = serde_json::json!({
            "token": token,
            "client_name": "pi-csr",
            "csr_pem": csr_pem,
        });
        let pair_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/pair")
                    .header("content-type", "application/json")
                    .body(Body::from(pair_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(pair_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(pair_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["issued_client_cert_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert!(body["server_ca_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert!(data_dir.join("pairings").join("pi-csr.crt").exists());
        assert!(data_dir.join("certs").join("agent-ca.crt").exists());
    }

    #[tokio::test]
    async fn mtls_server_accepts_issued_client_certificate() {
        if StdCommand::new("openssl").arg("version").output().is_err() {
            eprintln!("skipping mTLS test because openssl is not available");
            return;
        }

        let data_dir = test_data_dir("mtls");
        fs::create_dir_all(&data_dir).unwrap();
        let config = Config {
            tls_mode: TlsMode::Mtls,
            ..Config::default()
        };
        let openssl_config_path = ensure_openssl_config(&data_dir).unwrap();
        let key_path = data_dir.join("client.key");
        let csr_path = data_dir.join("client.csr");
        let output = StdCommand::new("openssl")
            .args([
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &path_arg(&key_path),
                "-out",
                &path_arg(&csr_path),
                "-config",
                &path_arg(&openssl_config_path),
                "-subj",
                "/CN=pi-mtls",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "openssl CSR generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let csr_pem = fs::read_to_string(&csr_path).unwrap();
        let issued = issue_client_certificate(&config, &data_dir, "pi-mtls", &csr_pem).unwrap();
        let tls_config = build_mtls_rustls_config(&config, &data_dir).unwrap();
        let app = build_app(
            config,
            data_dir.clone(),
            Arc::new(FixedPromptProvider {
                password: "mtls-secret".to_string(),
            }),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = Handle::new();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls_config)
                .handle(server_handle)
                .serve(app.into_make_service())
                .await
        });
        handle.listening().await.unwrap();

        let mut identity_pem = issued.client_cert_pem.clone();
        identity_pem.push_str(&fs::read_to_string(&key_path).unwrap());
        let client = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(issued.server_ca_pem.as_bytes()).unwrap(),
            )
            .identity(reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap())
            .build()
            .unwrap();
        let response = client
            .get(format!(
                "https://localhost:{}/ask?prompt=sudo&nonce=mtls",
                addr.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "mtls-secret\n");

        handle.graceful_shutdown(Some(Duration::from_secs(1)));
        server.await.unwrap().unwrap();
    }
}
