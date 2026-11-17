# gate のプロトコル

クライアント（`bwv`、bw-passkey、bw-autotype の SSH 鍵登録など）と、`bwvault-gate` の間の約束事。**実験的**で、互換性は、まだ保証しません。
実装の正は `bin/bwvault-gate`、実行できる仕様は `tests/test_gate.py` です。参照用のクライアントは `bin/bwv`（Python）と、bw-passkey の `src/gate.rs`（Rust）。

## 接続

- **ソケット**：`/run/bwvault-gate/gate.sock`（環境変数 `BWVAULT_GATE_SOCKET` で変えられる）。モードは 0666 ですが、gate が接続相手の uid を
  kernel から得て（`SO_PEERCRED`）、`BWVAULT_ALLOWED_UID` の1人以外は断ります。
- **クライアントは、ソケットの存在で、gate が入っているかを判断する**（ない環境では、従来の自前の経路に戻る）。
- **1接続に1要求。** 1行の JSON を送り、1行の JSON が返る（改行区切り）。接続は、答えのあとで閉じる。
- **待ち時間：** 本人確認の画面で待つので、長めに（150 秒を目安に）待つ。polkit の待ちは最大 120 秒。

```json
{"tty": null, "environment": null, "action": {"type": "GetEntry", "id": "…"}}
```
`tty` と `environment` は、rbw のプロトコルとの互換のために受け付けますが、**使いません**。gate は、あなたの環境変数（画面の情報など）を agent に渡しません。

応答は `{"type": "<種類>", …}`。失敗は `{"type": "Error", "error": "<文字列>"}`。

## 要求

承認の種類（`list`・`secret`・`write`・`ssh-sign`）と窓は、README の「確認の一覧」（英語版は "Confirmations"）を参照。

| `type` | 引数 | 応答 | 確認 | 備考 |
|---|---|---|---|---|
| `Version` | – | `Version` | なし | agent へそのまま |
| `CheckLock` / `Unlock` | – | `Ack` | なし | 施錠中なら、解錠してから `Ack`。解錠できなければ `Error` |
| `Lock` | – | `Ack` | なし | agent を施錠する |
| `Sync` | – | `Ack` | なし | agent が Bitwarden と同期する |
| `Login` | – | `Ack` | なし | 互換のため。ログインは bwvault 側で済ませてある |
| `ExportDb` | – | `Db`（`db`: 暗号化された項目の写し） | なし | トークン・保護された鍵は **含まれない**（`null`）。`rbw list` が読む DB の形 |
| `List` | – | `List`（`entries`） | **`list`** | 一覧を**1回の要求**で返す。`rbw list --raw` と同じ形（`id` `name` `user` `folder` `uris` `type`。名前順）。門が復号して、保管庫が変わる（DB の更新・`Lock`）まで覚えているので、2回目以降は速い（483 件で、項目ごとの復号を往復する約 0.6 秒が、ほぼ 0 になる） |
| `Decrypt` | `cipherstring`, `entry_key`, `org_id` | `Decrypt`（`plaintext`） | **`list`** | **項目名・ユーザー名・URI・フォルダ名の暗号文だけ**。秘密の欄は `Error`（`secret fields are only available through GetEntry`）。未知の暗号文も同じ |
| `GetEntry` | `id` | `Entry`（`entry`） | **`secret`**（項目ごと） | `rbw get --raw` と同じ形（下記） |
| `PasskeyList` | `force`（任意） | `Passkeys`（`passkeys`） | **`list`** | 秘密鍵は **含まれない**。gate が 10 分覚えている。`force` は、10 秒より古ければ取り直す |
| `PasskeyGet` | `ref` | `Passkey` | **`secret`**（パスキーごと） | 秘密鍵（暗号化を外した文字列）を返す |
| `AddEntry` | `kind` と、その種類の欄 | `Ack` | **`write`** | 暗号化と Bitwarden への送信は gate が行う（下記） |
| 上以外（`Encrypt`・`Quit`・`ClipboardStore`・`Register` など） | – | `Error`（`<type> is not allowed`） | – | 断る |

### `Entry`（`GetEntry` の応答）

```json
{"id": "…", "folder": "…"|null, "name": "…",
 "data": {…}|null, "fields": [{"name": "…", "value": "…", "type": "text|hidden|boolean|linked"|null}],
 "notes": "…"|null, "history": [{"last_used_date": "…", "password": "…"}]}
```
`data` は項目の種類で決まる。Login: `username` `password` `totp` `uris`（`[{"uri", "match_type"}]`）、Card: `cardholder_name` `number` `brand` `exp_month` `exp_year` `code`、
Identity: 17 の欄（`title` … `username`）、SshKey: `public_key` `fingerprint` `private_key`、SecureNote: `null`。

### `Passkeys` の1件

`ref`（`PasskeyGet` に渡す参照）、`item_name`、`rp_id`、`rp_name`、`credential_id`（保管庫の文字列のまま。UUID か `b64.…`）、
`user_handle`（base64url）、`user_name`、`user_display_name`。
`Passkey`（`PasskeyGet` の応答）：`key_value`（PKCS#8 DER の base64url）、`key_algorithm`、`key_curve`、`counter`、`discoverable`（どれも文字列）。

### `AddEntry`

- `kind: "login"`：`name`（必須）、`user`、`uri`、`folder`、`password`、`notes`
- `kind: "ssh"`：`name`（必須）、`folder`、`private_key`・`public_key`・`fingerprint`（必須）
- `kind: "passkey"`：`name`（必須）、`credential`（`credentialId` `keyType` `keyAlgorithm` `keyCurve` `keyValue` `rpId`（必須）`rpName` `userHandle`
  `userName` `userDisplayName` `counter` `discoverable`。すべて平文の文字列か `null`。ほかのキーは断る）

フォルダは、名前で探して、なければ作る。保存したあと、gate の DB と、パスキーの覚えを取り直す。

### エラーの文字列

`authorization denied`（本人確認が通らなかった・キャンセルされた）、`no such entry`、`no such passkey`、`bad request`、
`bwvault is locked and could not be unlocked …`、`secret fields are only available through GetEntry`、`<type> is not allowed`。
**`authorization denied` は、ユーザーが断った場合を含むので、エラー画面ではなく、取り消しとして扱う**ことを勧める。

## SSH エージェント

`/run/bwvault-gate/ssh-agent.sock`（`BWVAULT_SSH_SOCKET`）。標準の SSH エージェントのプロトコル（4 バイトの長さ＋種類＋中身）。
`REQUEST_IDENTITIES`（11）は agent へ通す。`SIGN_REQUEST`（13）は、**`ssh-sign` の確認**（鍵の項目名と、入ろうとしているユーザー名つき）を通してから agent へ渡す。
それ以外（鍵の追加・削除・ロックなど）は `SSH_AGENT_FAILURE`（5）。`SSH_AUTH_SOCK` をここに向ければ、`ssh`・`git` はそのまま使える（`systemd/user/bwvault-ssh.service`）。

## polkit

- アクション：`io.github.dobinnmushi.bwvault.{list,secret,write,ssh-sign}`（`polkit/…policy`）。既定は `auth_self`（キャッシュなし）。
- 確認画面の本文に、**詳細**（`item`＝項目名など、`requester`＝要求元）を入れる。**詳細を渡せるのは、アクションの所有者だけ**なので、
  各アクションに `org.freedesktop.policykit.owner = unix-user:bwvault` を付けている（付けないと、`CheckAuthorization` が断られる）。
- 承認は、アクションと対象に結び付け、時間を区切る。**ダイアログが「どの項目か」を言えること**が、設計の要（`design.md` の「途中で見つかって直した問題」の 1）。

## クライアントを書く人へ

- 確認（指紋・パスワード）は、gate が行う。**クライアントで本人確認を重ねない**。
- 秘密を取ったら、使ったあとすぐ捨てる。ログ・通知・ファイルに書かない（gate の記録にも、項目名や秘密は書いていない）。
- 一覧は `List` で取る（1回の要求）。`List` を知らない古い gate は `Error`（`List is not allowed`）を返すので、そのときだけ、従来の `ExportDb` の写し＋ `Decrypt`（`list` の確認）の組み合わせに戻る（`bin/bwv` の `list_entries` が参照実装）。
- gate がなければ（ソケットがなければ）、従来の経路に戻る。
