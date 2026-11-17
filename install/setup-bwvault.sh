#!/bin/bash
# bw-vault の導入・更新：rbw-agent を専用ユーザー bwvault の system サービスとして動かし、その前に門（gate）を置く。
#   sudo bash install/setup-bwvault.sh           入れる（何度実行しても同じ状態になる）
#   bash install/setup-bwvault.sh --check        何が変わるかだけを見る（root 不要。何も変更しない）
#   sudo bash install/setup-bwvault.sh --yes     最初の確認（yes の入力）を省く。/etc/pam.d/polkit-1 の確認は省けない
#
# このスクリプトは root で、あなたのホームのフォルダ（書き換えられるファイル）から、システムの大事な場所へコピーする。
# 悪意のあるプログラムが先にそのフォルダを書き換えていても、気づけるようにするため、入れる前に次のことをする:
#   1. 入れるファイルを、root 所有の一時置き場へ先に写す（表示と、実際に入れるものが、すり替わらないように）。
#   2. システムに入っている版との差分（新規なら SHA-256）を表示し、yes と入力しない限り、何も入れない。
#   3. システム全体の認証設定 /etc/pam.d/polkit-1 が変わるときは、別に、必ず対話で確認する。
#   4. rbw の実行ファイルは、控えてあるハッシュと照合する（違えば、ハッシュを表示して確認する）。
set -euo pipefail

MODE=install
ASSUME_YES=false
for a in "$@"; do
  case "$a" in
    --check) MODE=check ;;
    --yes) ASSUME_YES=true ;;
    *) echo "使い方: setup-bwvault.sh [--check] [--yes]" >&2; exit 2 ;;
  esac
done
if [ "$MODE" = install ]; then
  [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] || { echo "sudo で実行してください（見るだけなら --check）" >&2; exit 1; }
fi
SUDO_USER=${SUDO_USER:-$(id -un)}
HERE=$(cd "$(dirname "$0")/.." && pwd)
UHOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
LIB=/usr/local/lib/bwvault
STATE=/var/lib/bwvault

# 控えてある rbw 1.15.0 のハッシュ（2026-11-17 時点で、この環境で使っているもの。公式の配布物との照合は、していない）
RBW_SHA256=a2f3c2dcfcb8d39c5a493e5530a8206374722a80e87e3b24d4b6f7733bae498a
RBW_AGENT_SHA256=dd100b68897428829eefbe3191137ce4f899ee63c758d09730136a3442cd464d

SNAP=$(mktemp -d)                   # root 所有（mktemp は 0700）の一時置き場。ここに写したものだけを、表示し、入れる
trap 'rm -rf "$SNAP"' EXIT

is_elf() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(head -c4 "$1" | od -An -tx1 | tr -d ' \n')" = 7f454c46 ]; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
confirm() {
  # $1: 質問。$2 が always なら、--yes でも省かない（対話の端末が要る）
  if $ASSUME_YES && [ "${2:-}" != always ]; then return 0; fi
  [ -t 0 ] || { echo "対話の端末がないので、確認できません（中止します）" >&2; exit 1; }
  local ans
  read -r -p "$1 [yes/NO] " ans
  [ "$ans" = yes ]
}

# ---- 1. 入れるファイルを、先に一時置き場へ写す ----
# 「リポジトリ内の相対パス|システムの置き場所」
PLAN=(
  "bin/bwvault-admin|/usr/local/sbin/bwvault-admin"
  "bin/bwvault-gate|$LIB/bwvault-gate"
  "bin/pinentry-bwvault|$LIB/pinentry-bwvault"
  "polkit/io.github.dobinnmushi.bwvault.policy|/usr/share/polkit-1/actions/io.github.dobinnmushi.bwvault.policy"
  "pam/polkit-1|/etc/pam.d/polkit-1"
  "systemd/bwvault-agent.service|/etc/systemd/system/bwvault-agent.service"
  "systemd/bwvault-gate.service|/etc/systemd/system/bwvault-gate.service"
)
mkdir -p "$SNAP/files"
changed=()          # 変わるもの（番号）
for i in "${!PLAN[@]}"; do
  rel=${PLAN[$i]%%|*}
  [ -f "$HERE/$rel" ] && [ ! -L "$HERE/$rel" ] || { echo "$rel が通常のファイルではありません（中止します）" >&2; exit 1; }
  install -m 0600 "$HERE/$rel" "$SNAP/files/$i"
done

# rbw の実行ファイル（置き済みの本物は上書きしない）。ELF で、控えのハッシュと照合する
RBW_NEEDS=()        # 新しく置くもの
declare -A RBW_SRC
for name in rbw rbw-agent; do
  want=$RBW_SHA256; [ "$name" = rbw-agent ] && want=$RBW_AGENT_SHA256
  if is_elf "$LIB/$name"; then
    [ "$(sha "$LIB/$name")" = "$want" ] || echo "注意: 置き済みの $LIB/$name のハッシュが、控えと違います（上書きはしません）: $(sha "$LIB/$name")"
    continue
  fi
  for c in "$UHOME/.local/bin/$name" "$UHOME"/.local/bin/"$name".bak-*; do
    if is_elf "$c"; then install -m 0600 "$c" "$SNAP/$name"; RBW_SRC[$name]=$c; RBW_NEEDS+=("$name"); break; fi
  done
  [ -n "${RBW_SRC[$name]:-}" ] || { echo "本物の $name が見つかりません（~/.local/bin/$name か $name.bak-* が要ります）" >&2; exit 1; }
done

# ---- 2. 差分を見せる ----
echo "== 入れる内容（システムに入っている版との差分）=="
for i in "${!PLAN[@]}"; do
  dest=${PLAN[$i]#*|}; snap=$SNAP/files/$i
  if [ ! -e "$dest" ]; then
    echo "  新規  $dest   sha256:$(sha "$snap")"; changed+=("$i")
  elif ! cmp -s "$snap" "$dest"; then
    echo "  変更  $dest"; changed+=("$i")
    diff -u --label "現在 $dest" --label "新しい ${PLAN[$i]%%|*}" "$dest" "$snap" | sed -n '1,120p' | sed 's/^/        /' || true
    lines=$(diff -u "$dest" "$snap" | wc -l || true); [ "$lines" -le 120 ] || echo "        …（差分は全部で $lines 行。続きは diff -u $dest $snap で）"
  else
    echo "  変更なし  $dest"
  fi
done
for name in "${RBW_NEEDS[@]}"; do
  want=$RBW_SHA256; [ "$name" = rbw-agent ] && want=$RBW_AGENT_SHA256
  got=$(sha "$SNAP/$name")
  if [ "$got" = "$want" ]; then echo "  新規  $LIB/$name   ${RBW_SRC[$name]} から（控えのハッシュと一致）"
  else echo "  新規  $LIB/$name   ${RBW_SRC[$name]} から ※控えのハッシュと違います: $got"; RBW_MISMATCH=true; fi
done

# 何を再起動するか。gate 本体と gate の unit が変わったときだけ gate を再起動する（polkit の定義・PAM・bwvault-admin は、再起動なしで次から有効）。
# agent は、再起動すると解錠が外れるので、このスクリプトからは再起動しない
RESTART_GATE=false
AGENT_UNIT_CHANGED=false
for i in "${changed[@]}"; do
  case "${PLAN[$i]#*|}" in
    "$LIB/bwvault-gate"|/etc/systemd/system/bwvault-gate.service) RESTART_GATE=true ;;
    /etc/systemd/system/bwvault-agent.service) AGENT_UNIT_CHANGED=true ;;
  esac
done
if [ "${#changed[@]}" -eq 0 ] && [ "${#RBW_NEEDS[@]}" -eq 0 ]; then
  echo "変更はありません。"
else
  echo "== 反映のしかた =="
  if $RESTART_GATE; then echo "  bwvault-gate を再起動します（agent は再起動しないので、解錠は外れません）"
  else echo "  サービスの再起動は要りません（polkit の定義・PAM・bwvault-admin は、次に使われるときから有効です）"; fi
  if $AGENT_UNIT_CHANGED; then echo "  bwvault-agent の unit が変わります。反映には再起動が要ります（解錠が外れます。このスクリプトは再起動しません。次に使われるとき、自動で解錠されます）"; fi
fi
if [ "$MODE" = check ]; then
  [ "${#changed[@]}" -eq 0 ] && [ "${#RBW_NEEDS[@]}" -eq 0 ] && exit 0 || exit 1
fi

# ---- 3. 確認（変更があるときだけ）----
if [ "${#changed[@]}" -gt 0 ] || [ "${#RBW_NEEDS[@]}" -gt 0 ]; then
  confirm "上の内容を、root として、システムに入れます。差分を読んで、心当たりのない変更はありませんか？ 入れますか？" \
    || { echo "中止しました。何も変更していません。"; exit 1; }
  if [ "${RBW_MISMATCH:-false}" = true ]; then
    confirm "rbw の実行ファイルが、控えのハッシュと違います（更新したときは正常です）。このまま入れますか？" always \
      || { echo "中止しました。何も変更していません。"; exit 1; }
  fi
fi
for i in "${changed[@]}"; do
  if [ "${PLAN[$i]#*|}" = /etc/pam.d/polkit-1 ]; then
    confirm "システム全体の認証設定 /etc/pam.d/polkit-1 を書き換えます（sudo・polkit の認証が、これで決まります）。上の差分を確認しましたか？ 書き換えますか？" always \
      || { echo "中止しました。何も変更していません。"; exit 1; }
  fi
done

# ---- 4. 入れる（確認した写しから。リポジトリのファイルは、もう読まない）----
# 4-1. 専用ユーザー（ログイン不可）
id bwvault >/dev/null 2>&1 || useradd --system --user-group --home-dir "$STATE" --no-create-home \
  --shell /usr/sbin/nologin bwvault

# 4-2. バイナリは root 所有の場所に置く（~/.local/bin のように書き換えられない）
install -d -m 0755 -o root -g root "$LIB"
for name in "${RBW_NEEDS[@]}"; do install -m 0755 -o root -g root "$SNAP/$name" "$LIB/$name"; done
put() { install -D -m "$3" -o root -g root "$SNAP/files/$1" "$2"; }
for i in "${changed[@]}"; do
  case "${PLAN[$i]#*|}" in
    /usr/local/sbin/*|$LIB/*) mode=0755 ;;
    *) mode=0644 ;;
  esac
  put "$i" "${PLAN[$i]#*|}" "$mode"
done

# 4-3. 状態の置き場（bwvault だけが読める）と、rbw の端末の設定
install -d -m 0700 -o bwvault -g bwvault "$STATE" "$STATE/config" "$STATE/cache" "$STATE/data" "$STATE/data/rbw"
# 同じ PC なので、いまの rbw の端末 ID を引き継ぐ（Bitwarden への「端末登録」をやり直さずに済ませる）
# （シンボリックリンクは辿らない。root で読むので、ほかのファイルを指させて写させないため）
if [ ! -e "$STATE/data/rbw/device_id" ] && [ -f "$UHOME/.local/share/rbw/device_id" ] && [ ! -L "$UHOME/.local/share/rbw/device_id" ]; then
  install -m 0600 -o bwvault -g bwvault "$UHOME/.local/share/rbw/device_id" "$STATE/data/rbw/device_id"
fi

# 4-4. rbw の設定（サービスより先。agent は起動時に config.json を読む）。初回だけ
# （rbw config set は agent を再起動するので、実行のたびに解錠が外れてしまう）
if [ ! -e "$STATE/config/rbw/config.json" ]; then
  # -I: いま居るフォルダ（sudo を実行した、あなたのリポジトリ）や環境変数から、モジュールを読まない（json.py を置かれても動かない）
  EMAIL=$(python3 -I -c "import json,sys; print(json.load(open(sys.argv[1]))['email'])" "$UHOME/.config/rbw/config.json")
  bwvault-admin config set email "$EMAIL"
  bwvault-admin config set pinentry /usr/bin/pinentry-curses
  bwvault-admin config set lock_timeout 28800
fi

# 4-5. 許可する uid と、サービス
install -d -m 0755 /etc/bwvault
echo "BWVAULT_ALLOWED_UID=$(id -u "$SUDO_USER")" > /etc/bwvault/gate.env
systemctl daemon-reload
systemctl enable --now bwvault-agent.service
systemctl enable --now bwvault-gate.service
if $RESTART_GATE; then systemctl restart bwvault-gate.service; fi
if $AGENT_UNIT_CHANGED; then
  echo "注意: agent の unit が変わりました。反映するには sudo systemctl restart bwvault-agent（解錠が外れます。次に使うとき、自動で解錠されます）"
fi

echo
if [ -e /etc/bwvault/master.cred ]; then
  echo "できました。（マスターパスワードの封印は済んでいるので、ほかにやることはありません）"
else
  echo "できました。【初めて導入するときだけ】次を、この順に実行してください："
  echo "  sudo bwvault-admin login          # bwvault 側で Bitwarden にログイン（マスターパスワード、2段階認証）"
  echo "  sudo bwvault-admin sync"
  echo "  sudo bwvault-admin seal-master    # マスターパスワードを TPM2 で封印（以降は自動で解錠される）"
fi
