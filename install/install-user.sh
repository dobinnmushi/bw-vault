#!/bin/bash
# bw-vault のユーザー側の部品を入れる（sudo 不要）。何度実行しても同じ状態になる。
# 先に install/setup-bwvault.sh（sudo）と、bwvault のログイン・マスターパスワードの封印を済ませておく（README の「導入」）。
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="$HOME/.local/bin"
UNITS="$HOME/.config/systemd/user"
mkdir -p "$BIN" "$UNITS"

ln -sfn "$HERE/bin/bwv" "$BIN/bwv"
ln -sfn "$HERE/bin/bwv-pull" "$BIN/bwv-pull"

# rbw: 本物の実行ファイルがあれば、隣に退避してから、ラッパーに差し替える（rofi-rbw・bw-autotype などが呼ぶ rbw が、門につながる）
if [ -e "$BIN/rbw" ] && [ ! -L "$BIN/rbw" ]; then
  mv "$BIN/rbw" "$BIN/rbw.bak-$(date +%Y%m%d)"
  echo "旧 rbw を $BIN/rbw.bak-$(date +%Y%m%d) に退避しました"
fi
ln -sfn "$HERE/shim/rbw" "$BIN/rbw"

# SSH_AUTH_SOCK を門の SSH エージェントに向ける（ログインのたびに systemd が設定する）。旧 bw-ssh-agent があれば止める
if systemctl --user is-enabled bw-ssh-agent.socket >/dev/null 2>&1; then
  systemctl --user disable --now bw-ssh-agent.socket
fi
install -m 0644 "$HERE/systemd/user/bwvault-ssh.service" "$UNITS/bwvault-ssh.service"
systemctl --user daemon-reload
systemctl --user enable --now bwvault-ssh.service

"$HERE/bin/bwv-pull" --init-only
echo "できました。SSH_AUTH_SOCK は、ログインし直すと、すべてのアプリで門を指します。"
