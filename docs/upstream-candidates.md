# 本家（doy/rbw など）への Issue・PR の候補

実装が一通りできてから、使った内容をまとめて出す（2026-11-17 に合意）。投稿の前に、本家の最新の issue を検索して重複を確かめ、
外部への公開なので作者が確認してから送る。

## A. DB の保存を atomic にする（PR の第一候補）
- 場所: rbw 1.15.0 `src/db.rs` の `Db::save` / `Db::save_async`。`File::create`（切り詰め）→ `write_all` で、フラッシュも rename もしない。
  ソースに本家自身の `XXX need to make this atomic` がある。
- 症状: `rbw login` の直後の同期（`login_success` → `sync` の最初の `load_db`）で `failed to load db ... EOF while parsing a value at line 1 column 0`。
  DB にはトークンだけが書かれ、保管庫のデータが空のまま。`rbw sync` をやり直すと直る。
- 再現した環境: 専用ユーザーの system サービスで rbw-agent を動かし、初回ログイン（2026-11-17 16:08）。
- 未確認: 原因が「書き込み前の読み出し」であること（tokio::fs::File は flush せずに drop すると書き込みが終わらないことがある、が有力）。
  小さな再現と、本家の既存 issue（#148・#159 など、同種の EOF）との重複の確認が要る。
- 修正案: 同じディレクトリに一時ファイルを作って書き、flush（と sync）してから `rename`。

## B. agent 側の認証の拡張（Issue・議論。急がない）
- `state.rs` のコメントにある `master_password_reprompt` の仕組み（agent が自分の同期から暗号文の集合を作り、該当の復号だけ再確認する）を、
  全項目の秘密の欄や外部フック（polkit など）に広げられないか。
- 私たちは別プロセスの門（bwvault-gate）で実現したので、本家に入れる緊急性は低い。

## C. 欄の復号に失敗しても、終了コードが 0（要確認）
- 症状：rbw 1.15.0 の `rbw get <名前>` で、パスワードの復号に失敗すると、`WARN: failed to decrypt password: …` と
  `entry for '…' had no password` を標準エラーに出すが、**終了コードは 0**。スクリプトからは、失敗が「空の出力で成功」に見える。
- 観測した事実：終了コード 0（2026-11-17、gate が秘密の復号を断った状態で）。原因は、欄ごとの復号失敗を警告にして続ける作り（推測）。
- 未確認：本家の既存 issue との重複。仕様（警告で続ける）として意図されたものか。
- 出すなら：Issue（期待する動作の提案つき）。重い話ではない。

## 出さないと決めたもの
- 探索（`rbw get`）で全項目のノート・非隠しフィールドを復号する点: 隠しフィールドは `decrypt_search_cipher` で除外済みで、再確認の不具合は起きない。性能の話に過ぎない。
- ヘッドレスの agent のクリップボード警告（`couldn't create clipboard context`）: 動作に影響なし。

## 実装中に気づいたら足す
- （ここに追記）
