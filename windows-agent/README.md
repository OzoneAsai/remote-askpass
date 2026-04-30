# Windows Agent

Windows Agent receives `/ask` requests from Linux `remote-askpass`, asks the user for a password on Windows, and returns only the password body to the caller.

## Run

```powershell
cargo run -p remote-askpass-windows-agent -- serve
```

The default config is created at `%APPDATA%\RemoteAskpassBridge\config.json`.

On Windows, `serve` shows the native Windows Credential UI for each request. Use `--console-prompt` when you want terminal-only prompting instead.
`serve` also creates a tray icon by default. Use `--no-tray` for terminal-only/server-only runs.

For local tests:

```powershell
cargo run -p remote-askpass-windows-agent -- serve --listen 127.0.0.1:17878 --test-password test-password
curl.exe --insecure --get --data-urlencode "prompt=sudo password:" https://127.0.0.1:17878/ask
```

## Local API

- `GET /ask?prompt=...&nonce=...&host=...&user=...`: asks for a password and returns only `password + newline` on success.
- `GET /healthz`: returns `ok`.
- `GET /status`: returns runtime status, enabled flag, listen address, TLS mode, allowlist, and recent request count.
- `GET /recent`: returns recent request metadata. Passwords are not recorded.
- `POST /control/enable` and `POST /control/disable`: toggles runtime askpass handling without rewriting config.
- `POST /pairing/enable`: opens pairing and returns a one-time token. By default pairing stays open until explicitly disabled; set `pairing_window_seconds` to a positive value if you want auto-expiry.
- `POST /pairing/disable`: closes pairing.
- `POST /pair`: accepts `{ "token", "client_name", "public_key_pem" }` or `{ "token", "client_name", "csr_pem" }` while pairing is open. If `csr_pem` is supplied, the agent uses OpenSSL to create local CA material when needed and signs a client certificate under `%APPDATA%\RemoteAskpassBridge\pairings`.

If `allowed_hosts` is non-empty, `/ask` requires a `host` parameter and accepts only normalized exact matches from that list. Host comparison is case-insensitive and ignores one trailing dot.

## Tray

The Windows tray menu provides:

- Status
- Enable Askpass
- Disable Askpass
- Log Recent Requests
- Enable Pairing
- Disable Pairing
- Exit

Recent requests are logged to stderr/tracing output and never include passwords.

## mTLS

Set `tls_mode` to `mtls` to serve HTTPS with client certificate verification. The agent generates local CA/server material as needed, signs client CSRs during pairing, and trusts only client certificates issued by that local CA.

## Self-test

```powershell
cargo run -p remote-askpass-windows-agent -- self-test
cargo run -p remote-askpass-windows-agent -- wsl-self-test
cargo run -p remote-askpass-windows-agent -- wsl-sudo-self-test
cargo run -p remote-askpass-windows-agent -- wsl-install-helper
cargo run -p remote-askpass-windows-agent -- wsl-installed-helper-self-test
```

`self-test` starts an ephemeral local server, sends an `/ask` request to itself, verifies that the response body is exactly `password + newline`, and checks a rejected malformed request.
`wsl-self-test` starts an ephemeral Windows-side server, asks WSL for its Windows gateway, and verifies that WSL `curl` can reach `/ask`.
`wsl-sudo-self-test` reads `WSL-account` and `WSL-Password` from the local `.env`, starts an ephemeral Windows-side server, runs the real `linux-helper/remote-askpass` inside WSL with a temporary config, and verifies that `sudo -A` reaches `/ask`. The secret values are not logged.

`wsl-install-helper` installs `remote-askpass`, `rsudo`, and a working HTTPS-over-WSL config into the selected WSL account. Existing files are backed up with a timestamp suffix before replacement. Start the Windows agent with `--listen 0.0.0.0:17878` for this WSL-local config. When no CA path is configured yet, the helper uses curl `--insecure`; the channel is still encrypted and never falls back to plaintext HTTP.

`wsl-installed-helper-self-test` starts an ephemeral Windows-side server on `0.0.0.0:17878` and verifies that the installed WSL `rsudo true` path reaches `/ask`.

## Startup

```powershell
cargo run -p remote-askpass-windows-agent -- register-startup
cargo run -p remote-askpass-windows-agent -- unregister-startup
```

This creates or removes a Startup folder `.cmd` launcher for the current executable. The implementation intentionally avoids launching PowerShell for startup registration.

## Current scope

This is a Windows-first MVP of the Agent model: config, HTTP API, request validation, native Windows Credential UI prompt, prompt provider abstraction, startup registration, tray menu, single-instance lock, recent request recording, runtime enable/disable, pairing-window record capture, certificate issuance from CSR, and self-test support.

The agent always serves encrypted TLS in `serve`, including legacy configs that still say `disabled_for_local_testing`. Use `tls_mode = "server_tls"` for encrypted server-only TLS, or `tls_mode = "mtls"` when the client must also authenticate with a certificate.
