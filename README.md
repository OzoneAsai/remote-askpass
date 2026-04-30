# remote-askpass

Remote Askpass Bridge の仕様書は `docs/spec.md` にあります。

## Current implementation status

このリポジトリでは Linux 側 helper と Windows Agent MVP を提供しています。

- `linux-helper/remote-askpass`: `sudo -A` から呼び出す askpass helper
- `linux-helper/rsudo`: command hint を渡す wrapper
- `linux-helper/install.sh`: ローカルインストールスクリプト
- `windows-agent`: Windows 側で `/ask` を受ける Agent

## Linuxでの使い方

Linux 側では `remote-askpass` を `sudo -A` の askpass helper として使います。

前提:

- `curl`
- `python3`
- `sudo`
- Windows 側で `remote-askpass-windows-agent` が起動していること

インストール:

```bash
cd linux-helper
./install.sh
```

最小実行:

```bash
SUDO_ASKPASS="$HOME/.local/bin/remote-askpass" sudo -A whoami
```

`rsudo` を使うと command hint 付きで呼べます。

```bash
$HOME/.local/bin/rsudo whoami
```

設定ファイルは `~/.config/remote-askpass/config.json` です。Windows 側が mTLS で待ち受ける場合は、client certificate / key / CA certificate の path をこの設定へ入れます。

WSL を Linux 側として使う場合は、Windows 側から次のコマンドで helper と config をまとめて配置できます。

```powershell
cargo run -p remote-askpass-windows-agent -- wsl-install-helper
```

このコマンドは既存の `~/.local/bin/remote-askpass`、`~/.local/bin/rsudo`、`~/.config/remote-askpass/config.json` を timestamp 付きでバックアップしてから更新します。

## Windowsでの使い方

Windows 側では `remote-askpass-windows-agent` を常駐させて `/ask` を受けます。

前提:

- Rust / Cargo
- `openssl` を PATH から呼べること
- WSL 連携を使う場合は `wsl.exe`

基本確認:

```powershell
cargo run -p remote-askpass-windows-agent -- self-test
```

通常起動:

```powershell
cargo run -p remote-askpass-windows-agent -- serve
```

通常の `serve` は tray icon を作成し、Windows native Credential UI を出します。端末入力だけで動かしたい場合は `--console-prompt`、tray なしで動かしたい場合は `--no-tray` を使います。

WSL ローカル構成で使う場合:

```powershell
cargo run -p remote-askpass-windows-agent -- serve --listen 0.0.0.0:17878
```

この場合も通信は `https://...` です。相手がまだ CA を持っていない段階では helper が curl の `--insecure` を使いますが、平文 HTTP には落としません。

WSL 連携の確認:

```powershell
cargo run -p remote-askpass-windows-agent -- wsl-install-helper
cargo run -p remote-askpass-windows-agent -- wsl-installed-helper-self-test
```

ローカルで「自分を自分で叩く」テストを行う場合:

```powershell
cargo run -p remote-askpass-windows-agent -- serve --listen 127.0.0.1:17878 --test-password test-password
curl.exe --insecure --get --data-urlencode "prompt=sudo password:" https://127.0.0.1:17878/ask
```

設定ファイルは `%APPDATA%\RemoteAskpassBridge\config.json` に作られます。Windows Agent は `/status`、`/recent`、`/control/enable`、`/control/disable`、`/pairing/enable`、`/pairing/disable`、`/pair` も提供します。pairing は既定では手動で閉じるまで有効です。`csr_pem` を渡した場合は OpenSSL でローカル CA と client certificate を作り、`tls_mode = "mtls"` では HTTPS listener が client certificate を検証します。

`allowed_hosts` を設定した場合、`/ask` は `host` パラメータ必須になります。比較は大小文字と末尾ドットを正規化した完全一致です。
