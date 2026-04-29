# Remote Askpass Bridge 仕様書

## 1. 概要

Remote Askpass Bridge は、Raspberry Pi などの Linux 環境で実行される `sudo -A` の askpass 要求を、Windows 側の常駐アプリケーションへ転送し、ユーザーが Windows 上で入力した sudo パスワードを Linux 側へ一時的に返却するための仕組みである。

想定用途は、SSH 経由、VS Code Remote、タスクランナー、ボット、GUI ランチャーなど、Linux 側に直接 TTY が存在しない、または標準入力から sudo パスワードを渡したくないケースである。

本システムは sudo パスワードを保存しない。要求ごとに Windows 側で明示的な入力または承認を求め、Linux 側の askpass helper は stdout にパスワード文字列のみを出力する。

## 2. 目的

### 2.1 解決したい問題

Linux 側で次のようなコマンドを実行したい。

```bash
SUDO_ASKPASS="$HOME/.local/bin/remote-askpass" sudo -A systemctl restart my.service
```

ただし、パスワード入力 UI は Linux 側ではなく Windows 側に出したい。

### 2.2 目標

- Windows 側に常駐アプリを置く。
- Windows 起動時に自動起動できる。
- タスクトレイに常駐する。
- Raspberry Pi 側の `sudo -A` から呼ばれる askpass helper を提供する。
- SSH reverse tunnel 経由で Windows 側へ askpass 要求を転送する。
- Windows 側で prompt、接続元、要求内容を表示する。
- パスワードを保存しない。
- stdout に余計な文字を出さない。
- 失敗時は安全に拒否する。

## 3. 非目標

- sudoers の設定管理そのものは扱わない。
- sudo パスワードの永続保存はしない。
- Windows 資格情報マネージャーへの保存は初期版では行わない。
- 複数ユーザーの権限管理システムにはしない。
- インターネット越しの公開 API にはしない。
- SSH の代替認証機構にはしない。

## 4. 全体構成

### 4.1 標準構成: overlay direct mode + app-layer mTLS

```text
Windows
  Remote Askpass Agent
    - Tailscale IP / Remote.It endpoint で待ち受け
    - tray icon
    - startup registration
    - password prompt dialog
    - mTLS server certificate
       ↑
       │ HTTPS over Tailscale / Remote.It
       │ app-layer mTLS
       │
Raspberry Pi Linux
  remote-askpass helper
    - sudo -A から起動
    - client certificate で Agent に直接接続
    - 受け取った password を stdout に出す
       ↑
       │
  sudo -A command
```

標準構成では SSH を経由しない。Tailscale または Remote.It は、Windows Agent の待ち受け port へ RPI から到達するための overlay transport として使う。

Windows Agent は HTTPS server として待ち受ける。RPI helper は `curl` または Rust helper で `/ask` に直接接続する。接続認証は mTLS で行う。

### 4.2 SSH fallback: reverse tunnel mode

SSH reverse tunnel は fallback とする。常用路ではない。SSH は接続維持コストと設定の重さがあるため、Tailscale / Remote.It が使える環境では overlay direct mode を優先する。

## 5. コンポーネント

### 5.1 Windows Agent

#### 役割

- askpass request を受け取る。
- ユーザーへ入力ダイアログを表示する。
- パスワードをレスポンスとして返す。
- タスクトレイに常駐する。
- Windows スタートアップへ登録・解除できる。
- 状態表示、ログ表示、終了操作を提供する。

#### 実装方針

Windows Agent は Rust で実装する。依存の少ない単体 exe として配布できる軽量常駐アプリを目指す。

### 5.2 Linux askpass helper

#### 役割

- `sudo -A` から起動される。
- 第一引数として渡される prompt を受け取る。
- Agent に request を送る。
- 成功時、受け取った password を stdout に出す。
- 失敗時、非ゼロ exit で終了する。

#### 重要制約

`sudo -A` 用 askpass helper は stdout にパスワード以外を出してはならない。

### 5.3 SSH reverse tunnel

Raspberry Pi 側から Windows 側 Agent へ到達するための fallback 通信路として利用する。

## 6. 通信仕様

### 6.1 標準プロトコル

標準プロトコルは HTTPS + mTLS とする。標準は overlay direct mode とし、SSH は既定では使わない。

### 6.2 Ask API

Endpoint:

```text
GET /ask?prompt=<urlencoded-prompt>&nonce=<nonce>&host=<host>&user=<user>
```

成功時レスポンス本文は平文パスワード（末尾改行付き）。拒否 403、タイムアウト 408、異常 500。

### 6.3 Pairing API

初回ペアリング時のみ短時間有効化する。

Endpoint:

```text
POST /pair
```

Windows Agent がローカル CA として client certificate を発行し、RPI helper は private key をローカル生成して公開鍵のみ送信する。

## 7. Windows Agent UI 仕様

### 7.1 トレイアイコン

メニュー項目:

- Status
- Enable / Disable Askpass
- Show Recent Requests
- Settings
- Register Startup
- Unregister Startup
- Exit

### 7.2 パスワード入力ダイアログ

タイトル `Remote sudo request`、host/user/prompt/request time/command hint を表示し、Approve・Deny を提供する。

## 8. スタートアップ仕様

初期版は Startup folder にショートカットを作成して自動起動を実現する。

## 9. 設定仕様

Windows 設定: `%APPDATA%\RemoteAskpassBridge\config.json`。
Linux 設定: `~/.config/remote-askpass/config.json`。

## 10. セキュリティ方針

- ネットワーク層（Tailscale ACL / Remote.It / Firewall）+ アプリ層（mTLS / allowlist）の二層制御。
- パスワード保存禁止。
- ログに password / 秘密鍵 / secret token を出さない。
- タイムアウトは dialog 30秒、helper 35秒、connect 3秒、pairing 120秒。

## 11. Linux helper 詳細仕様

- `prompt="${1:-sudo password:}"`
- 成功時は stdout に password+改行のみ。
- 失敗時は stdout 空、stderr にエラー、非ゼロ終了。

## 12. Windows Agent 詳細仕様

- 起動時: 設定読込 → 単一起動確認 → server 起動 → tray 生成 → startup反映 → ready。
- request処理: validate → dialog → approve/deny/timeout を HTTP ステータスで返却 → recent request 記録。

## 13. エラー処理

Windows Agent:

- disabled: 403
- missing prompt: 400
- already prompting: 409
- timeout: 408
- internal error: 500

Linux helper:

- curl未導入 / 接続失敗 / HTTPエラー / 空レスポンスは stderr 出力して exit 1。

## 14. インストール仕様

Windows:

- `%LOCALAPPDATA%\RemoteAskpassBridge\RemoteAskpassBridge.exe`
- `%APPDATA%\RemoteAskpassBridge\config.json`

Linux:

- `~/.local/bin/remote-askpass`
- `~/.config/remote-askpass/config.json`

## 15. Transport 利用仕様

- **Tailscale direct mode** を第一優先。
- **Remote.It direct mode** をサポート。
- **SSH reverse tunnel** は fallback。

## 16. コマンドヒント

初期版では optional。wrapper 使用時のみ `REMOTE_ASKPASS_COMMAND_HINT` を送る。

## 17. 受け入れ条件

- Pairing、基本動作、Startup、安全性の各要件を満たすこと。

## 18. MVP 範囲

Windows Agent: HTTPS server / mTLS / local CA / pairing / dialog / tray / startup。
Linux helper: bash+curl もしくは Rust、mTLS、必要パラメータ送信、stdout strict。

## 19. 将来拡張

request signing、allowlist 強化、Windows Hello/YubiKey、installer、auto update など。

## 20. リポジトリ構成案

```text
remote-askpass-bridge/
  README.md
  docs/spec.md
  docs/protocol.md
  docs/security.md
  windows-agent/
  linux-helper/
  examples/
```

## 21. 初期実装メモ

- Rust + tokio + axum を基本候補。
- release build: `cargo build --release`。
- release時の console 非表示に `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]` を検討。

## 22. 命名

初期名は **Remote Askpass Bridge** とする。
