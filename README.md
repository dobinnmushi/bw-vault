# bw-vault

Bitwarden（[rbw](https://github.com/doy/rbw)）の保管庫の鍵を、**自分のユーザーとは別のユーザー `bwvault`** に置き、
秘密を出す前に **polkit（sudo と同じ認証：指紋、だめならパスワード）で本人確認**をする仕組みです。

## 3つの部品

Bitwarden を Linux のデスクトップ（GNOME / Wayland）で、パスワードの入力・パスキー・SSH まで使えるようにする、3つのリポジトリの1つです。
bw-vault は、その**認証の部分**で、残りの2つは、それぞれ単独でも動きます。

| リポジトリ | 役割 | bw-vault がないとき |
|---|---|---|
| **bw-vault**（これ） | 保管庫の鍵を別ユーザーに置き、秘密を出す前に polkit で確認する門。SSH エージェントも兼ねる | – |
| [bw-autotype](https://github.com/dobinnmushi/bw-autotype) | ホットキーで、ユーザー名・パスワード・TOTP を任意のアプリに入力。新規登録 | 単独で動く（自前で指紋を確認） |
| [bw-passkey](https://github.com/dobinnmushi/bw-passkey) | 保管庫のパスキーを使う、仮想の FIDO2 セキュリティキー | 単独で動く（自前で指紋を確認） |

一緒に使うと、入力・パスキー・SSH の**すべてが、同じ門と、同じ確認**（指紋、だめならパスワード）を通ります。
bw-autotype と bw-passkey は、bw-vault のソケットがあれば自動で門を使い、なければ従来のまま動きます。
導入は、bw-vault（下の「導入」）→ bw-autotype・bw-passkey（それぞれの README）の順です。
門との約束事は [`docs/protocol.md`](docs/protocol.md) に書いてあり、別のクライアントも作れます。

## なぜ要るか

rbw-agent は、解錠すると保管庫の鍵をメモリに持ち、**同じユーザーで動くどのプログラムの「復号して」にも応えます**。
ホットキーの指紋確認（bw-autotype）は入口の画面を守るだけで、別のプログラムが直接 `rbw get` を呼ぶことは止められません。
Linux には、同じユーザーの中でプログラムを区別する権限の境界がないので（ファイルの権限・ソケットの権限・プログラム内の確認は、
同じユーザーなら迂回できます）、鍵と復号の能力を**別のユーザー**に移し、そこが認証を要求する形にしました。

## 守るもの・守らないもの

**守る**（同じユーザーで動く、認証を通していないプログラムから）:
- 項目の秘密：パスワード・TOTP・ノート・カード・SSH 秘密鍵・隠しフィールド・履歴・パスキーの秘密鍵
- 項目名・ユーザー名・URL・フォルダ名・パスキーのサイト名の一覧
- 保管庫の暗号化された鍵・アクセストークン（持ち出してのマスターパスワードの総当たりを防ぐ）
- 復号・暗号化・停止を頼める agent のソケット

**守らない**:
- root と、sudo を使える人。カーネルの脆弱性。物理的な攻撃（封印したマスターパスワードは、root なら `systemd-creds decrypt` で復号できます）
- 承認した瞬間に、平文が呼び出し元（入力するプログラム）へ渡ること。キーロガー
- 確認の画面を、あなたが何も考えずに通すこと（画面には、**どの項目か**と**要求元のプログラム**が出ます。見て判断する前提です）。
  導入・更新の `yes` も同じで、差分を読んで、心当たりのない変更がないことを確かめてから入力してください
- 一覧の承認の窓（既定 20 秒）の間は、同じユーザーの全プロセスが、名前の一覧を見られます（秘密は出ません）

## 仕組み

```
あなたのユーザー側                              bwvault（専用ユーザー、system サービス）
 rbw（ラッパー） rofi-rbw bw-autotype bwv ─┐      ┌ bwvault-gate ── polkit で確認 ──→ あなたの画面（指紋）
 bw-passkey  ssh / git ───────────────────┴─ソケット→│   ├ 一覧：確認（list）を通して返す
                                                      │   ├ 秘密：項目ごとに確認（secret）を通して返す
                                                      │   ├ 書き込み：確認（write）を通して暗号化・送信
                                                      │   └ SSH 署名：確認（ssh-sign）を通して agent へ
                                                      └ rbw-agent（無改造）── 保管庫の鍵・トークン・DB
```

- **bwvault-agent**：公式の rbw-agent を、専用ユーザーで動かします（`ProtectHome`・`ProtectProc`・`CapabilityBoundingSet=` など。
  `systemd-analyze security` で 3.1）。バイナリは root 所有の `/usr/local/lib/bwvault/` に置きます。
- **bwvault-gate**：あなたのユーザーが使える唯一の入口（`/run/bwvault-gate/`）。rbw と同じ JSON 行のプロトコルを話し、
  要求ごとに許可を決めます（3.3）。接続相手の pid と uid は、kernel が教える `SO_PEERCRED` で得ます。
- **自動解錠**：マスターパスワードを `systemd-creds`（TPM2 とホスト鍵）で封印し、使われたとき gate が agent を解錠させます。
  `lock_timeout` は 300 秒（使われなければ施錠）。解錠自体は秘密を出さないので、本人確認は要りません。
- **ユーザー側**：`rbw` のラッパー（`shim/rbw`）が、`get`・`code`・`add` を `bwv` に差し替え、`list`・`sync` の前後に、
  トークンと鍵を除いた暗号化された写し（`~/.cache/rbw-vault/`）を取り直します。プロファイルは `RBW_PROFILE=vault`。

### 確認の一覧

| polkit アクション | いつ | 画面に出るもの | 承認の結び付け先と時間 |
|---|---|---|---|
| `…bwvault.list` | 項目名などの一覧、パスキーの一覧 | 要求元 | **ユーザー全体**で 20 秒（1回の操作で、別々のプロセスが一覧を取るため） |
| `…bwvault.secret` | 項目の取り出し、パスキーの秘密鍵 | **項目名**（パスキーはサイト名とユーザー名）、要求元 | **プロセス＋項目**ごとに 10 秒。別の項目は必ず聞き直す |
| `…bwvault.write` | 項目・パスキーの新規作成 | 新規登録の種類と名前、要求元 | プロセス＋名前ごとに 10 秒 |
| `…bwvault.ssh-sign` | SSH 署名 | 鍵の項目名と、入ろうとしているユーザー名 | **親プロセス＋鍵**ごとに 30 秒（`git push` が ssh を何度か起動しても、同じ git の子なら聞き直さない） |

指紋は 5 回まで試せ、だめならパスワードです（`pam/polkit-1`。sudo・ログインの設定は変えません）。
承認を「項目」に結び付けているのは意図的です。ダイアログの項目名を見て、別の項目を狙う要求を見破れるようにするためです。

## 導入

必要なもの：rbw 1.15.0（`~/.local/bin/rbw` と `rbw-agent`。ELF の実行ファイル）、polkit と fprintd（指紋）、TPM2 と、`systemd-creds`・`LoadCredentialEncrypted=` が使える systemd（動作確認は 259）、
`python3-gi`、`pinentry-curses`。

```sh
bash install/setup-bwvault.sh --check  # 何が入るかを見る（root 不要）
sudo bash install/setup-bwvault.sh     # bwvault ユーザー・サービス・polkit の定義を入れる。差分を表示して、yes の入力を求める
sudo bwvault-admin login               # bwvault 側で Bitwarden にログイン（マスターパスワード、2段階認証）
sudo bwvault-admin sync
sudo bwvault-admin seal-master         # マスターパスワードを TPM2 で封印 → 以降は自動で解錠される
install/install-user.sh                # ユーザー側：rbw のラッパー・bwv・SSH_AUTH_SOCK（sudo 不要）。ログインし直す
```

bw-autotype を使うなら、`~/.config/bw-autotype/config.toml` の `[auth] method = "none"`（確認は gate が行うので、二重にしない）。
bw-passkey は、gate のソケットがあれば自動で gate を使います。

### 導入スクリプトの安全確認

`setup-bwvault.sh` は、root で、あなたのフォルダにあるファイルを、システムの大事な場所（`/etc/pam.d/polkit-1` を含む）へコピーします。
悪意のあるプログラムが、先にそのフォルダを書き換えていても気づけるように、次のようにしています。

- 入れるファイルを、**root 所有の一時置き場に先に写し**、その写しを表示し、その写しだけを入れる（表示と実際の内容がすり替わらない）。
- システムの版との**差分**（新規なら SHA-256）を表示し、`yes` と入力しない限り、何も入れない。
- `/etc/pam.d/polkit-1` が変わるときは、**別の確認**を、必ず対話で求める（`--yes` でも省けない。端末がなければ中止）。
- rbw の実行ファイルは、控えてあるハッシュと照合する（違えば、確認する）。
- 試験：`tests/test_setup.py`（改ざんが差分に出ること、確認を省けないこと）。

## 日常

| 操作 | コマンド |
|---|---|
| 状態 | `systemctl status bwvault-agent bwvault-gate`、`journalctl -u bwvault-gate`（記録に項目名は残らず、短い識別子 `[a1b2c3d4]` だけ） |
| 手で施錠・解錠・同期 | `sudo bwvault-admin lock` / `unlock` / `sync` |
| マスターパスワードを変えた | `sudo bwvault-admin seal-master` をやり直す |
| 確認の窓の長さを変える | `/etc/bwvault/gate.env` に `BWVAULT_LIST_SECONDS` `BWVAULT_GROUP_SECONDS` `BWVAULT_SSH_GROUP_SECONDS` を書き、`sudo systemctl restart bwvault-gate` |
| 一覧が遅い | 一覧（`rbw list --raw`）は、門が復号して覚えているので、2回目以降は速い。遅いときは、`systemctl status bwvault-gate` で、起動し直されていないかを見る（更新や再起動の直後の1回目は、復号し直す） |
| gate を更新した | まず `bash install/setup-bwvault.sh --check`（root 不要。システムの版との差分だけを表示）。読んでから `sudo bash install/setup-bwvault.sh`（差分と、何を再起動するかを表示し、`yes` の入力を求める。再起動するのは、gate 本体・gate の unit が変わったときの gate だけで、agent は再起動しません（解錠が外れるため）。置き済みの本物の rbw は上書きしません） |
| rbw を更新した | 新しい `rbw`・`rbw-agent` を、`sudo install -m 0755 … /usr/local/lib/bwvault/` で置き直す |
| ファームウェア更新などで解錠できなくなった | `sudo bwvault-admin seal-master`（TPM の PCR には結び付けていません） |

## 使えないもの・制限

- 標準の `rbw get` は、秘密の欄を断られます（`bwv get`・`bwv code` を使う。ラッパーが自動で差し替えます）。`--full`・`--field`・`--clipboard` は未対応。
- TOTP は、base32 と `otpauth://` の形式（SHA1・SHA256・SHA512）だけです。Steam Guard（`steam://`）は未対応。
- `rbw edit` / `remove` / `search` は使えません。`rbw add` は、ログイン項目だけです（SSH 鍵は bw-autotype 経由）。
- パスキーのログインは、一覧と鍵の取り出しで、確認が 2 回です。
- gate は Bitwarden の API に直接つなぎます（項目の新規作成・パスキーの一覧のため）。
- 一覧の承認の窓の間は、同じユーザーの全プロセスが名前の一覧を見られます。窓を短くすると、確認が増えます。
- 偽の認証ダイアログに、パスワードを打たされる攻撃は防げません（指紋が通る限りは、打つ場面がありません）。
- SSH 署名は `ssh-keygen -Y sign` までを実機で確認しました。GitHub などの実サーバーへのログインは未確認です。

## 試験

```sh
tests/run.sh      # 偽の agent・偽の API・偽の polkit を使う。sudo も、実際の保管庫も要らない
```

gate の約束（上の確認の一覧、承認の結び付け、解錠、書き込み、SSH、記録に名前を書かないこと）を確かめます。
主な不具合（記録に名前を書く、一覧の確認を外す、承認を項目に結び付けない）を、わざと入れた gate で、試験が失敗することも確かめています。

## 構成

| | |
|---|---|
| `bin/bwvault-gate` | 門（Python、標準ライブラリ＋Gio）。bwvault の system サービス |
| `bin/pinentry-bwvault` | rbw-agent が pinentry として呼ぶ。封印されたマスターパスワードを返す |
| `bin/bwvault-admin` | `sudo bwvault-admin login / unlock / sync / seal-master / …`（bwvault としての rbw） |
| `bin/bwv`, `bin/bwv-pull` | ユーザー側：項目の取り出し・コード・追加と、暗号化された写しの更新 |
| `shim/rbw` | ユーザー側：`~/.local/bin/rbw` に置くラッパー |
| `systemd/` | `bwvault-agent.service`、`bwvault-gate.service`、`user/bwvault-ssh.service` |
| `polkit/`, `pam/` | polkit のアクション定義（4つ）、polkit 用の PAM 設定 |
| `install/` | `setup-bwvault.sh`（sudo）、`install-user.sh` |
| `docs/` | 設計の判断と教訓（`design.md`）、本家への Issue・PR の候補（`upstream-candidates.md`） |

## 取り外し

```sh
systemctl --user disable --now bwvault-ssh.service && rm ~/.config/systemd/user/bwvault-ssh.service
mv ~/.local/bin/rbw.bak-YYYYMMDD ~/.local/bin/rbw          # 旧 rbw に戻す（ラッパーのリンクを置き換える）
sudo systemctl disable --now bwvault-gate bwvault-agent
sudo rm -r /etc/systemd/system/bwvault-*.service* /etc/bwvault /usr/local/lib/bwvault /usr/local/sbin/bwvault-admin \
           /usr/share/polkit-1/actions/io.github.dobinnmushi.bwvault.policy /etc/pam.d/polkit-1
sudo userdel bwvault && sudo rm -r /var/lib/bwvault          # 保管庫のデータ（トークン・暗号化された DB）も消えます
```

その後、旧 rbw で `rbw login` からやり直してください。

## ライセンスと謝辞

rbw を無改造で使います（rbw のライセンスに従います）。このプロジェクト自体のライセンスは未定です。gate は、rbw のプロトコル（`src/protocol.rs`）と、agent 側で項目ごとに再確認する設計（`state.rs` のコメント）に学びました。
