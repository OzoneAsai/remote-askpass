# remote-askpass

Remote Askpass Bridge の仕様書は `docs/spec.md` にあります。

## Current implementation status

このリポジトリでは Linux 側 helper と Windows Agent MVP を提供しています。

- `linux-helper/remote-askpass`: `sudo -A` から呼び出す askpass helper
- `linux-helper/rsudo`: command hint を渡す wrapper
- `linux-helper/install.sh`: ローカルインストールスクリプト
- `windows-agent`: Windows 側で `/ask` を受ける Agent

## Quick start (Linux)

```bash
cd linux-helper
./install.sh
SUDO_ASKPASS="$HOME/.local/bin/remote-askpass" sudo -A whoami
```

## Quick start (Windows Agent)

```powershell
cargo run -p remote-askpass-windows-agent -- self-test
cargo run -p remote-askpass-windows-agent -- wsl-install-helper
cargo run -p remote-askpass-windows-agent -- wsl-installed-helper-self-test
cargo run -p remote-askpass-windows-agent -- serve
```

通常の `serve` はtray iconを作成し、Windows native Credential UIを出します。端末入力だけで動かしたい場合は `--console-prompt`、trayなしで動かしたい場合は `--no-tray` を使います。

WSLローカル構成で使う場合は、Agentを `--listen 0.0.0.0:17878` で起動してください。`wsl-install-helper` は既存のWSL側helper/configをtimestamp付きでバックアップしてから、`~/.local/bin/remote-askpass`、`~/.local/bin/rsudo`、`~/.config/remote-askpass/config.json` を配置します。

ローカルで「自分を自分で叩く」テストを行う場合:

```powershell
cargo run -p remote-askpass-windows-agent -- serve --listen 127.0.0.1:17878 --test-password test-password
curl.exe --get --data-urlencode "prompt=sudo password:" http://127.0.0.1:17878/ask
```

Windows Agent は `/status`、`/recent`、`/control/enable`、`/control/disable`、`/pairing/enable`、`/pairing/disable`、`/pair` も提供します。pairing は既定では手動で閉じるまで有効です。`csr_pem` を渡した場合はOpenSSLでローカルCAとクライアント証明書を作り、`tls_mode = "mtls"` ではHTTPS listenerがclient certificateを検証します。

`allowed_hosts` を設定した場合、`/ask` は `host` パラメータ必須になります。比較は大小文字と末尾ドットを正規化した完全一致です。
