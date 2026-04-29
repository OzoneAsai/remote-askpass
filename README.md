# remote-askpass

Remote Askpass Bridge の仕様書は `docs/spec.md` にあります。

## Current implementation status

このリポジトリでは Linux 側 helper の初期実装を提供しています。

- `linux-helper/remote-askpass`: `sudo -A` から呼び出す askpass helper
- `linux-helper/rsudo`: command hint を渡す wrapper
- `linux-helper/install.sh`: ローカルインストールスクリプト

## Quick start (Linux)

```bash
cd linux-helper
./install.sh
SUDO_ASKPASS="$HOME/.local/bin/remote-askpass" sudo -A whoami
```
