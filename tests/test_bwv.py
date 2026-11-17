#!/usr/bin/env python3
"""bwv の項目の探し方の試験（rbw get と同じ規則: 完全一致 → 部分一致、ユーザー名・フォルダで絞る）。"""
import os
import sys
import types
from importlib.machinery import SourceFileLoader

bwv = types.ModuleType("bwv")
SourceFileLoader("bwv", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "bwv")).exec_module(bwv)

UUID = "11111111-1111-1111-1111-111111111111"
E = lambda i, n, u=None, f=None: {"id": i, "name": n, "user": u, "folder": f, "uris": []}
L = [E("1", "github", "alice"), E("2", "github", "bob"), E("3", "gitlab", "alice", "work"), E("4", "gitlab", "alice", "home"),
     E("5", "example account"), E("6", "Example Sync"), E(UUID, "uuid-target", "carol")]
ok = True


def t(name, got, want):
    global ok
    ok &= got == want
    print(("OK  " if got == want else f"NG  (got {got}, want {want}) ") + name)


def find(needle, user=None, folder=None, ic=False, kind="name"):
    try:
        return bwv.find_entry(L, (kind, needle), user, folder, ic)["id"]
    except SystemExit:
        return "ERR"


t("完全一致が1件", find("example account"), "5")
t("名前が同じでも、ユーザー名で1件に絞る", find("github", "bob"), "2")
t("名前だけで複数なら失敗", find("github"), "ERR")
t("フォルダで絞る", find("gitlab", None, "work"), "3")
t("部分一致（完全一致がないとき）", find("account"), "5")
t("大文字小文字は -i のときだけ無視", (find("example sync"), find("example sync", ic=True)), ("ERR", "6"))
t("見つからない", find("nothing"), "ERR")
t("UUID で指定", find(UUID, kind="uuid"), UUID)
t("UUID が合わなければ、名前としても探す", find("uuid-target", kind="uuid"), UUID)
t("rbw のパスワード入力の解析: 1行目がパスワード、残りがノート（# の行は除く）",
  bwv.parse_editor("pw\n\nnote1\n# comment\nnote2\n"), ("pw", "note1\nnote2"))
t("ノートがなければ None", bwv.parse_editor("pw\n"), ("pw", None))

# --- TOTP（RFC 6238 の付録 B の試験値。秘密は ASCII の "12345678901234567890"（SHA256 は 32 文字、SHA512 は 64 文字の繰り返し）。8 桁の値の下 6 桁を見る）
import base64
b32 = lambda raw: base64.b32encode(raw).decode()
sec1, sec256, sec512 = b"12345678901234567890", b"12345678901234567890123456789012", b"1234567890123456789012345678901234567890123456789012345678901234"
t("TOTP SHA1 T=59（RFC 6238: 94287082）", bwv.totp_code(b32(sec1), now=59), "287082")
t("TOTP SHA1 T=1111111109（07081804）", bwv.totp_code(b32(sec1), now=1111111109), "081804")
t("TOTP SHA1 T=20000000000（65353130）", bwv.totp_code(b32(sec1), now=20000000000), "353130")
uri = lambda raw, algo, digits=8: f"otpauth://totp/x?secret={b32(raw)}&algorithm={algo}&digits={digits}&period=30"
t("TOTP SHA256 T=59（46119246）", bwv.totp_code(uri(sec256, "SHA256"), now=59), "46119246")
t("TOTP SHA512 T=59（90693936）", bwv.totp_code(uri(sec512, "SHA512"), now=59), "90693936")
t("otpauth の既定値（SHA1・6桁・30秒）", bwv.totp_code(f"otpauth://totp/Example:me?secret={b32(sec1)}&issuer=Example", now=59), "287082")
t("空白・小文字・= なしの base32 も読める", bwv.totp_code(" " + b32(sec1).lower().rstrip("=")[:8] + " " + b32(sec1).lower().rstrip("=")[8:], now=59), "287082")
def raises(f):
    try: f(); return False
    except ValueError: return True
t("対応しない形式（steam://）は ValueError", raises(lambda: bwv.totp_code("steam://ABCDEFGH")), True)
t("対応しないアルゴリズムは ValueError", raises(lambda: bwv.totp_code(f"otpauth://totp/x?secret={b32(sec1)}&algorithm=MD5")), True)
print("結果:", "全部OK" if ok else "失敗あり")
sys.exit(0 if ok else 1)
