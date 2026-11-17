#!/bin/bash
# bw-vault の隔離の試作：rbw-agent を専用ユーザー bwvault の system サービスとして動かす。
# root で実行する（sudo bash setup-bwvault.sh）。何度実行しても同じ状態になる。
set -euo pipefail
[ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] || { echo "sudo で実行してください" >&2; exit 1; }
HERE=$(cd "$(dirname "$0")/.." && pwd)
UHOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
LIB=/usr/local/lib/bwvault
STATE=/var/lib/bwvault

# 1. 専用ユーザー（ログイン不可）
id bwvault >/dev/null 2>&1 || useradd --system --user-group --home-dir "$STATE" --no-create-home \
  --shell /usr/sbin/nologin bwvault

# 2. バイナリは root 所有の場所に置く（~/.local/bin のように書き換えられない）
install -d -m 0755 -o root -g root "$LIB"
# 置くのは本物の実行ファイル（ELF）だけ。~/.local/bin/rbw は、bw-vault のラッパーに差し替わることがあるので、
# ラッパーを取り違えて本物を上書きしないよう、種類を確かめる。置き済みの本物は上書きしない
is_elf() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(head -c4 "$1" | od -An -tx1 | tr -d ' \n')" = 7f454c46 ]; }
for name in rbw rbw-agent; do
  if ! is_elf "$LIB/$name"; then
    for c in "$UHOME/.local/bin/$name" "$UHOME"/.local/bin/"$name".bak-*; do
      if is_elf "$c"; then install -m 0755 -o root -g root "$c" "$LIB/$name"; break; fi
    done
    is_elf "$LIB/$name" || { echo "本物の $name が見つかりません（~/.local/bin/$name か $name.bak-* が要ります）" >&2; exit 1; }
  fi
done
install -m 0755 -o root -g root "$HERE/bin/bwvault-admin" /usr/local/sbin/bwvault-admin

# 3. 状態の置き場（bwvault だけが読める）と、rbw の端末の設定
install -d -m 0700 -o bwvault -g bwvault "$STATE" "$STATE/config" "$STATE/cache" "$STATE/data" "$STATE/data/rbw"
# 同じ PC なので、いまの rbw の端末 ID を引き継ぐ（Bitwarden への「端末登録」をやり直さずに済ませる。
# 並走中にいまの rbw と干渉するかは未確認。干渉したら rbw register をやり直す）
if [ ! -e "$STATE/data/rbw/device_id" ] && [ -r "$UHOME/.local/share/rbw/device_id" ]; then
  install -m 0600 -o bwvault -g bwvault "$UHOME/.local/share/rbw/device_id" "$STATE/data/rbw/device_id"
fi

# 4. rbw の設定（サービスより先。agent は起動時に config.json を読む）（メールアドレスはいまの rbw と同じ。pinentry は初回ログイン用の端末版）
# 設定は初回だけ入れる（rbw config set は agent を再起動するので、実行のたびに解錠が外れてしまう）
if [ ! -e "$STATE/config/rbw/config.json" ]; then
  EMAIL=$(python3 -c "import json,sys; print(json.load(open('$UHOME/.config/rbw/config.json'))['email'])")
  bwvault-admin config set email "$EMAIL"
  bwvault-admin config set pinentry /usr/bin/pinentry-curses
  bwvault-admin config set lock_timeout 28800
fi

# 5. サービス
install -m 0644 "$HERE/systemd/bwvault-agent.service" /etc/systemd/system/bwvault-agent.service
systemctl daemon-reload
systemctl enable --now bwvault-agent.service

# 6. 門（あなたのユーザーが使うソケット。秘密の復号の前に polkit で確認する）
install -m 0755 -o root -g root "$HERE/bin/bwvault-gate" "$LIB/bwvault-gate"
install -m 0755 -o root -g root "$HERE/bin/pinentry-bwvault" "$LIB/pinentry-bwvault"
install -d -m 0755 /etc/bwvault
echo "BWVAULT_ALLOWED_UID=$(id -u "$SUDO_USER")" > /etc/bwvault/gate.env
install -m 0644 "$HERE/polkit/io.github.dobinnmushi.bwvault.policy" /usr/share/polkit-1/actions/
install -m 0644 "$HERE/pam/polkit-1" /etc/pam.d/polkit-1
install -m 0644 "$HERE/systemd/bwvault-gate.service" /etc/systemd/system/bwvault-gate.service
systemctl daemon-reload
systemctl enable --now bwvault-gate.service
systemctl restart bwvault-gate.service

echo
echo "できました。bwvault にログイン・解錠が済んでいなければ（端末で）："
echo "  sudo bwvault-admin login     # マスターパスワード（と、求められれば2段階認証）を入力"
echo "  sudo bwvault-admin sync"
echo "  sudo bwvault-admin unlock"
