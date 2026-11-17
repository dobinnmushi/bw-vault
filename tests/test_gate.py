#!/usr/bin/env python3
"""bwvault-gate の試験。偽の rbw-agent・偽の Bitwarden API・偽の polkit を使うので、sudo も実際の保管庫も要らない。

ソケット・DB・設定は、一時ディレクトリにだけ作る。終了コードは、全部通れば 0。
確かめること（gate の約束）:
  - 一覧（項目名など）は、一覧の確認（list）を通して初めて返る。承認はユーザー全体の窓。
  - 秘密は Decrypt では出ない。GetEntry は項目ごとに確認が出て、別の項目へ承認を引き継げない。
  - 解錠できなければ、秘密も名前も出ない。施錠中は、使われたとき自動で解錠する。
  - 項目・パスキーの新規作成は、確認を通してから、平文を API に出さずに送る。
  - SSH 署名は、確認（親プロセス＋鍵ごと）を通してから通す。許可していない要求は断る。
  - 記録（journal）に、項目名などを書かない。
"""
import base64
import http.server
import json
import os
import shutil
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time
import types
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
D = tempfile.mkdtemp(prefix="bwvault-gate-test-")
os.makedirs(D + "/db")
LIST, SECRET, WRITE, SSH = (f"io.github.dobinnmushi.bwvault.{a}" for a in ("list", "secret", "write", "ssh-sign"))


def S(b):
    return struct.pack(">I", len(b)) + b


# ---- 偽の Bitwarden API ----
api_log = []
api_state = {"fail401": 0}


def cred(n):
    return {"credentialId": f"2.cid{n}|a|b", "keyType": "2.kt|a|b", "keyAlgorithm": "2.alg|a|b", "keyCurve": "2.crv|a|b",
            "keyValue": f"2.kv{n}|a|b", "rpId": f"2.rp{n}|a|b", "rpName": f"2.rpn{n}|a|b", "userHandle": f"2.uh{n}|a|b",
            "userName": f"2.un{n}|a|b", "userDisplayName": f"2.udn{n}|a|b", "counter": "2.cnt|a|b", "discoverable": "2.disc|a|b"}


class API(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        api_log.append(("GET", self.path, None, self.headers.get("Authorization")))
        if self.path == "/api/folders":
            self._send(200, {"data": [{"id": "f1", "name": "2.fold|x|y"}]})
        elif self.path == "/api/sync":
            self._send(200, {"Ciphers": [
                {"Id": "c1", "Type": 1, "Name": "2.pkname|a|b", "Key": None, "Login": {"Fido2Credentials": [cred(0), cred(1)]}},
                {"Id": "c2", "Type": 1, "Name": "2.del|a|b", "DeletedDate": "2026-01-01", "Login": {"Fido2Credentials": [cred(9)]}},
                {"Id": "c3", "Type": 1, "Name": "2.nopk|a|b", "Login": {}}]})
        else:
            self._send(404, {})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        api_log.append(("POST", self.path, body, self.headers.get("Authorization")))
        if api_state["fail401"] > 0 and self.path == "/api/ciphers":
            api_state["fail401"] -= 1
            return self._send(401, {})
        self._send(200, {"id": "newfolder-id"} if self.path == "/api/folders" else {"id": "c1"})


api_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
PORT = api_server.server_address[1]
threading.Thread(target=api_server.serve_forever, daemon=True).start()
json.dump({"base_url": f"http://127.0.0.1:{PORT}"}, open(D + "/rbw-config.json", "w"))

os.environ.update(BWVAULT_RBW_CONFIG=D + "/rbw-config.json", BWVAULT_AGENT_SOCKET=D + "/agent.sock",
                  BWVAULT_GATE_SOCKET=D + "/gate.sock", BWVAULT_DB_DIR=D + "/db", BWVAULT_ALLOWED_UID=str(os.getuid()),
                  BWVAULT_SSH_SOCKET=D + "/ssh-gate.sock", BWVAULT_AGENT_SSH_SOCKET=D + "/ssh-agent.sock")
gate = types.ModuleType("gate")
SourceFileLoader("gate", os.path.join(HERE, "..", "bin", "bwvault-gate")).exec_module(gate)

# ---- 合成した DB（暗号文の代わりに "2.名前|a|b" の形。偽の agent は "PT:" を付けて返す）----
BLOB = S(b"ssh-ed25519") + S(b"K" * 32)
PUB = "ssh-ed25519 " + base64.b64encode(BLOB).decode() + " comment"
e1 = {"id": "e1", "org_id": None, "folder": "2.folder|a|b", "folder_id": None, "name": "2.name|a|b",
      "data": {"Login": {"username": "2.user|a|b", "password": "2.pass|a|b", "totp": "2.totp|a|b",
                         "uris": [{"uri": "2.uri|a|b", "match_type": None}]}},
      "fields": [{"ty": None, "name": "2.fname|a|b", "value": "2.fval|a|b", "linked_id": None}], "notes": "2.notes|a|b",
      "history": [{"last_used_date": "x", "password": "2.hist|a|b"}], "key": "2.key|a|b", "master_password_reprompt": "None"}
e2 = {"id": "e2", "org_id": None, "folder": None, "folder_id": None, "name": "2.name2|a|b", "data": "SecureNote",
      "fields": [], "notes": "2.notes2|a|b", "history": [], "key": None, "master_password_reprompt": "None"}
e3 = {"id": "e3", "org_id": None, "folder": None, "folder_id": None, "name": "2.sshname|a|b",
      "data": {"SshKey": {"private_key": "2.sshpriv|a|b", "public_key": "2.sshpub|a|b", "fingerprint": "2.sshfp|a|b"}},
      "fields": [], "notes": None, "history": [], "key": None, "master_password_reprompt": "None"}
json.dump({"access_token": "SECRET-TOKEN", "refresh_token": "SECRET-R", "protected_key": "2.pk|a|b", "protected_org_keys": {},
           "entries": [e1, e2, e3]}, open(D + "/db/default:x@example.com.json", "w"))

# ---- 偽の rbw-agent ----
calls = []
STATE = {"locked": True, "fail_unlock": False}


class Agent(socketserver.StreamRequestHandler):
    def handle(self):
        req = json.loads(self.rfile.readline())
        a = req["action"]
        calls.append(a)
        assert req["environment"] == {"tty": None, "env_vars": []}, "あなたの環境変数が agent に漏れている"
        t = a["type"]
        if t == "CheckLock":
            r = {"type": "Error", "error": "agent is locked"} if STATE["locked"] else {"type": "Ack"}
        elif t == "Unlock":
            if STATE["fail_unlock"]:
                r = {"type": "Error", "error": "pinentry failed"}
            else:
                STATE["locked"] = False
                r = {"type": "Ack"}
        elif t == "Lock":
            STATE["locked"] = True
            r = {"type": "Ack"}
        elif t == "Encrypt":
            r = {"type": "Encrypt", "cipherstring": "ENC(" + a["plaintext"] + ")"}
        elif t == "Decrypt":
            if STATE["locked"]:
                r = {"type": "Error", "error": "agent is locked"}
            elif a["cipherstring"] == "2.sshpub|a|b":
                r = {"type": "Decrypt", "plaintext": PUB}
            else:
                r = {"type": "Decrypt", "plaintext": "PT:" + a["cipherstring"]}
        else:
            r = {"type": "Ack"}
        self.wfile.write(json.dumps(r).encode() + b"\n")


ssh_up = []


class SshUp(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                (n,) = struct.unpack(">I", self.request.recv(4))
                body = self.request.recv(n)
                ssh_up.append(body)
                ans = bytes([12]) + struct.pack(">I", 0) if body[0] == 11 else bytes([14]) + S(b"SIG")
                self.request.sendall(struct.pack(">I", len(ans)) + ans)
        except Exception:
            pass


class Srv(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


for cls, path, h in ((Srv, "/agent.sock", Agent), (Srv, "/ssh-agent.sock", SshUp),
                     (gate.Server, "/gate.sock", gate.Handler), (gate.SshServer, "/ssh-gate.sock", gate.SshHandler)):
    threading.Thread(target=cls(D + path, h).serve_forever, daemon=True).start()
time.sleep(0.3)

# ---- 偽の polkit と、記録の収集 ----
polk, logs = [], []
gate.log = lambda m: logs.append(m)


def approve(ok=True):
    gate._approved.clear()
    polk.clear()
    gate.polkit_check = (lambda pid, start, aid, details: (polk.append((aid, details["item"])) or True)) if ok \
        else (lambda pid, start, aid, details: (polk.append((aid, details["item"])) or False))


def asked(action):
    return [x for x in polk if x[0] == action]


def ask(action):
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(D + "/gate.sock")
        s.settimeout(30)
        s.sendall(json.dumps({"tty": None, "environment": {"tty": "/dev/pts/9", "env_vars": []}, "action": action}).encode() + b"\n")
        return json.loads(s.makefile().readline())


def dec(cs):
    return ask({"type": "Decrypt", "cipherstring": cs, "entry_key": None, "org_id": None})


def dcalls(n):
    return [c["cipherstring"] for c in calls[n:] if c["type"] == "Decrypt"]


ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("OK  " if cond else "NG  ") + name)


# ===== 一覧（項目名・ユーザー名・URI・フォルダ名）は、一覧の確認を通して返る =====
approve()
r = dec("2.name|a|b")
check("項目名の復号は、一覧の確認（list）を通して初めて通る", r.get("plaintext") == "PT:2.name|a|b" and polk == [(LIST, "一覧")])
for cs in ("2.user|a|b", "2.uri|a|b", "2.folder|a|b", "2.name2|a|b"):
    check(f"20 秒の窓の間は、聞き直さずに通る: {cs}", dec(cs).get("plaintext") == "PT:" + cs)
check("窓はユーザー全体で共有（確認は1回だけ）", len(polk) == 1)
approve(False)
n = len(calls)
r = dec("2.name|a|b")
check("一覧の確認が通らなければ、項目名は agent に届かない", r.get("type") == "Error" and dcalls(n) == [])
check("ExportDb（暗号化された写し）は確認なしで返る", ask({"type": "ExportDb"}).get("type") == "Db")
db = ask({"type": "ExportDb"})["db"]
check("ExportDb にトークン・保護された鍵がない", all(db[k] is None for k in ("access_token", "refresh_token", "protected_key", "protected_private_key"))
      and "SECRET" not in json.dumps(db) and len(db["entries"]) == 3)

# ===== 秘密は Decrypt では出ない =====
approve()
n = len(calls)
for cs in ("2.pass|a|b", "2.totp|a|b", "2.notes|a|b", "2.fname|a|b", "2.fval|a|b", "2.hist|a|b", "2.key|a|b", "2.notes2|a|b", "2.unknown|a|b"):
    check(f"断る（秘密・未知の Decrypt）: {cs}", dec(cs).get("type") == "Error")
check("秘密の Decrypt は、確認も出さず、agent にも届けない", polk == [] and dcalls(n) == [])
for t in ("Encrypt", "Quit", "ClipboardStore", "Register", "Frobnicate"):
    n = len(calls)
    check(f"断る（許可していない要求）: {t}", ask({"type": t, "plaintext": "x", "text": "x"}).get("type") == "Error" and len(calls) == n)

# ===== GetEntry: 承認は項目ごと =====
approve()
r1 = ask({"type": "GetEntry", "id": "e1"})
check("GetEntry は、項目の名前を出した secret の確認が1回出る", asked(SECRET) == [(SECRET, "PT:2.name|a|b")])
ask({"type": "GetEntry", "id": "e1"})
check("同じ項目を続けて頼んでも、まとめ期間内は聞き直さない", len(asked(SECRET)) == 1)
r2 = ask({"type": "GetEntry", "id": "e2"})
check("別の項目は必ず聞き直す（承認を引き継げない）", asked(SECRET) == [(SECRET, "PT:2.name|a|b"), (SECRET, "PT:2.name2|a|b")])
e = r1["entry"]
check("rbw get --raw と同じキー", list(e) == ["id", "folder", "name", "data", "fields", "notes", "history"])
check("Login の data", e["data"] == {"username": "PT:2.user|a|b", "password": "PT:2.pass|a|b", "totp": "PT:2.totp|a|b",
                                    "uris": [{"uri": "PT:2.uri|a|b", "match_type": None}]})
check("fields / notes / history / folder", e["fields"] == [{"name": "PT:2.fname|a|b", "value": "PT:2.fval|a|b", "type": None}]
      and e["notes"] == "PT:2.notes|a|b" and e["history"] == [{"last_used_date": "x", "password": "PT:2.hist|a|b"}]
      and e["folder"] == "PT:2.folder|a|b")
check("SecureNote の data は null", r2["entry"]["data"] is None and r2["entry"]["notes"] == "PT:2.notes2|a|b")
check("存在しない ID は断る", ask({"type": "GetEntry", "id": "nope"}).get("type") == "Error")
approve(False)
n = len(calls)
r = ask({"type": "GetEntry", "id": "e1"})
check("本人確認が通らなければ Error で、秘密の暗号文は agent に届かない", r.get("type") == "Error" and all(c == "2.name|a|b" for c in dcalls(n)))


def boom(*a):
    raise RuntimeError("polkit down")


approve()
gate.polkit_check = boom
n = len(calls)
r = ask({"type": "GetEntry", "id": "e2"})
check("polkit が失敗したら拒否（秘密は返らない）", r.get("type") == "Error" and all(c == "2.name2|a|b" for c in dcalls(n)))

# ===== 自動解錠 =====
approve()
STATE["locked"] = True
n = len(calls)
r = dec("2.name|a|b")
check("施錠中でも、使われたら自動で解錠して通す", r.get("plaintext") == "PT:2.name|a|b"
      and [c["type"] for c in calls[n:]] == ["CheckLock", "CheckLock", "Unlock", "Decrypt"])
n = len(calls)
dec("2.user|a|b")
check("解錠済みなら Unlock は呼ばない", [c["type"] for c in calls[n:]] == ["CheckLock", "Decrypt"])
ask({"type": "Lock"})
check("Lock は agent へ通る", STATE["locked"] is True)
STATE["fail_unlock"] = True
n = len(calls)
r = dec("2.name|a|b")
check("解錠できなければ断る（Decrypt は agent に届かない）", r.get("type") == "Error" and "Decrypt" not in [c["type"] for c in calls[n:]])
approve()
n = len(calls)
r = ask({"type": "GetEntry", "id": "e1"})
check("解錠できなければ GetEntry も断る（本人確認の前に）", r.get("type") == "Error" and polk == [] and "Decrypt" not in [c["type"] for c in calls[n:]])
STATE["fail_unlock"] = False
r = ask({"type": "Unlock"})
check("Unlock 要求も自動解錠して Ack", r.get("type") == "Ack" and STATE["locked"] is False)
check("Login は Ack", ask({"type": "Login"}).get("type") == "Ack")
n = len(calls)
check("CheckLock は agent へ", ask({"type": "CheckLock"}).get("type") == "Ack" and len(calls) == n + 1)

# ===== 項目の新規作成 =====
approve()
r = ask({"type": "AddEntry", "kind": "login", "name": "site", "user": "me", "uri": "https://x.example",
         "folder": "PT:2.fold|x|y", "password": "pw1", "notes": "memo"})
c = [x for x in api_log if x[0] == "POST" and x[1] == "/api/ciphers"][-1]
body = c[2]
check("AddEntry(login) は write の確認が出て、項目名つき", r.get("type") == "Ack" and polk == [(WRITE, "新規登録（ログイン）: site")])
check("既存フォルダを使う（フォルダは作らない）", body["folderId"] == "f1" and not [x for x in api_log if x[0] == "POST" and x[1] == "/api/folders"])
check("全欄が agent で暗号化されて送られる（平文は API に出ない）", body["name"] == "ENC(site)" and body["notes"] == "ENC(memo)" and body["type"] == 1
      and body["login"] == {"Username": "ENC(me)", "Password": "ENC(pw1)", "Totp": None, "Uris": [{"Uri": "ENC(https://x.example)", "Match": None}]}
      and "pw1" not in json.dumps(body).replace("ENC(pw1)", ""))
check("トークンは bwvault の DB のもの", c[3] == "Bearer SECRET-TOKEN")
check("登録後に agent の同期を呼ぶ", calls[-1]["type"] == "Sync")
r = ask({"type": "AddEntry", "kind": "login", "name": "site2", "password": "pw2", "folder": "newfolder"})
check("無いフォルダは作ってから使う", r.get("type") == "Ack"
      and [x for x in api_log if x[0] == "POST" and x[1] == "/api/folders"][-1][2] == {"name": "ENC(newfolder)"}
      and [x for x in api_log if x[1] == "/api/ciphers"][-1][2]["folderId"] == "newfolder-id")
api_state["fail401"] = 1
n_api = len(api_log)
n_sync = len([c for c in calls if c["type"] == "Sync"])
r = ask({"type": "AddEntry", "kind": "login", "name": "site3", "password": "pw3"})
check("401（トークン切れ）なら agent に同期させて1回だけやり直す", r.get("type") == "Ack"
      and len([x for x in api_log[n_api:] if x[1] == "/api/ciphers"]) == 2 and len([c for c in calls if c["type"] == "Sync"]) == n_sync + 2)
r = ask({"type": "AddEntry", "kind": "ssh", "name": "mykey", "folder": "", "private_key": "PRIV", "public_key": "PUB", "fingerprint": "FP"})
c = [x for x in api_log if x[1] == "/api/ciphers"][-1][2]
check("AddEntry(ssh) の形", r.get("type") == "Ack" and c["type"] == 5 and c["folderId"] is None
      and c["sshKey"] == {"privateKey": "ENC(PRIV)", "publicKey": "ENC(PUB)", "keyFingerprint": "ENC(FP)"})
n_api = len(api_log)
for bad in ({"kind": "x", "name": "a"}, {"kind": "login"}, {"kind": "login", "name": "a", "password": 5}, {"kind": "ssh", "name": "a"}):
    check(f"不正な要求は断る: {bad}", ask({"type": "AddEntry", **bad}).get("type") == "Error")
check("不正な要求では暗号文を API に送らない", not [x for x in api_log[n_api:] if x[1] == "/api/ciphers"])
approve(False)
n_api = len(api_log)
r = ask({"type": "AddEntry", "kind": "login", "name": "denied", "password": "p"})
check("本人確認が通らなければ、何も送らない", r.get("type") == "Error" and len(api_log) == n_api)

# ===== パスキー =====
approve()
r = ask({"type": "PasskeyList"})
pks = r.get("passkeys", [])
check("PasskeyList は一覧の確認を通して返る。削除済み・パスキーなしの項目を除いて 2 件",
      r.get("type") == "Passkeys" and [p["ref"] for p in pks] == ["c1#0", "c1#1"] and [a for a, _ in polk] == [LIST])
check("メタ情報（サイト名・ユーザー名・credentialId・userHandle）が平文で入る",
      pks[0]["rp_id"] == "PT:2.rp0|a|b" and pks[0]["user_name"] == "PT:2.un0|a|b" and pks[0]["credential_id"] == "PT:2.cid0|a|b"
      and pks[0]["user_handle"] == "PT:2.uh0|a|b" and pks[0]["item_name"] == "PT:2.pkname|a|b")
check("一覧に秘密鍵は入らず、秘密鍵の暗号文を agent に復号させてもいない",
      "kv0" not in json.dumps(r) and "kv1" not in json.dumps(r) and not [c for c in calls if c["type"] == "Decrypt" and c["cipherstring"].startswith("2.kv")])
r = ask({"type": "PasskeyGet", "ref": "c1#0"})
check("PasskeyGet は、サイト名とユーザー名を出した secret の確認を通して秘密鍵を返す", r.get("type") == "Passkey" and r["key_value"] == "PT:2.kv0|a|b"
      and asked(SECRET) == [(SECRET, "パスキー PT:2.rp0|a|b（PT:2.un0|a|b）")])
r2 = ask({"type": "PasskeyGet", "ref": "c1#1"})
check("別のパスキーは聞き直す（承認を引き継げない）", len(asked(SECRET)) == 2 and r2["key_value"] == "PT:2.kv1|a|b")
ask({"type": "PasskeyGet", "ref": "c1#0"})
check("同じパスキーの再要求は、まとめ期間内は聞かない", len(asked(SECRET)) == 2)
check("存在しない ref は断る", ask({"type": "PasskeyGet", "ref": "c9#0"}).get("type") == "Error")
approve(False)
n = len(calls)
r = ask({"type": "PasskeyGet", "ref": "c1#1"})
check("本人確認が通らなければ、秘密鍵は復号されず返らない",
      r.get("type") == "Error" and not [c for c in calls[n:] if c["type"] == "Decrypt" and c["cipherstring"].startswith("2.kv")])
approve(False)
n_api = len(api_log)
check("パスキーの一覧も、一覧の確認が通らなければ返らない", ask({"type": "PasskeyList"}).get("type") == "Error")
approve()
cred_new = {"credentialId": "b64.AQID", "keyType": "public-key", "keyAlgorithm": "ECDSA", "keyCurve": "P-256", "keyValue": "DERKEY",
            "rpId": "example.com", "rpName": "Example", "userHandle": "UH", "userName": "me@example.com", "userDisplayName": None,
            "counter": "0", "discoverable": "true"}
n_get = len([x for x in api_log if x[:2] == ("GET", "/api/sync")])
r = ask({"type": "AddEntry", "kind": "passkey", "name": "Example", "credential": cred_new})
fc = [x for x in api_log if x[1] == "/api/ciphers"][-1][2]
check("AddEntry(passkey) は write の確認が出る", r.get("type") == "Ack" and asked(WRITE) == [(WRITE, "新規登録（パスキー）: Example")])
check("全欄が暗号化されて送られる（秘密鍵の平文は API に出ない）",
      fc["login"]["fido2Credentials"][0]["keyValue"] == "ENC(DERKEY)" and fc["login"]["fido2Credentials"][0]["userDisplayName"] is None
      and "DERKEY" not in json.dumps(fc).replace("ENC(DERKEY)", "") and fc["login"]["fido2Credentials"][0]["creationDate"].endswith("Z")
      and fc["login"]["uris"] == [{"uri": "ENC(https://example.com)", "match": None}])
ask({"type": "PasskeyList"})
check("登録したあと、一覧は取り直される", len([x for x in api_log if x[:2] == ("GET", "/api/sync")]) == n_get + 1)
for bad in ({"credential": {"rpId": "a", "evil": "x"}}, {"credential": {"keyValue": "k"}}, {"credential": {"rpId": "a", "counter": 0}}, {"credential": "x"}):
    check(f"不正な資格情報は断る: {bad}", ask({"type": "AddEntry", "kind": "passkey", "name": "x", **bad}).get("type") == "Error")

# ===== SSH エージェント =====
def sshc():
    c = socket.socket(socket.AF_UNIX)
    c.connect(D + "/ssh-gate.sock")
    c.settimeout(20)
    return c


def ssh_rt(c, body):
    c.sendall(struct.pack(">I", len(body)) + body)
    (n,) = struct.unpack(">I", c.recv(4))
    return c.recv(n)


def sign_body(blob, user=b"git"):
    data = S(b"\x00" * 32) + bytes([50]) + S(user) + S(b"ssh-connection") + S(b"publickey")
    return bytes([13]) + S(blob) + S(data) + struct.pack(">I", 0)


orig_parent = gate.parent_of
approve()
ssh_up.clear()
c = sshc()
r = ssh_rt(c, bytes([11]))
check("鍵の一覧は確認なしで通す", r[0] == 12 and ssh_up[-1][0] == 11 and polk == [])
r = ssh_rt(c, sign_body(BLOB))
check("署名は ssh-sign の確認が出て、鍵の項目名と相手のユーザー名つき", polk == [(SSH, "PT:2.sshname|a|b（git として）")])
check("確認が通れば、署名が上流から返る", r[0] == 14 and ssh_up[-1][0] == 13)
r = ssh_rt(c, sign_body(BLOB, b"other"))
check("同じ親・同じ鍵なら、まとめ期間内は聞き直さない", len(polk) == 1 and r[0] == 14)
gate.parent_of = lambda pid: (999999, 1)
r = ssh_rt(c, sign_body(BLOB))
check("別の親から来た署名は、承認を引き継げず聞き直す", len(polk) == 2 and r[0] == 14)
n_up = len(ssh_up)
r = ssh_rt(c, sign_body(S(b"ssh-ed25519") + S(b"X" * 32)))
check("保管庫にない鍵の署名は断る（上流に届かない）", r[0] == 5 and len(ssh_up) == n_up and len(polk) == 2)
for kind in (17, 18, 19, 22, 23, 27):
    r = ssh_rt(c, bytes([kind]) + b"xxxx")
    check(f"鍵の追加・削除・ロックなど（種類 {kind}）は断る", r[0] == 5 and len(ssh_up) == n_up)
c.close()
approve()
gate.parent_of = lambda pid: (999997, 1)
c = sshc()
sshsig = bytes([13]) + S(BLOB) + S(b"SSHSIG" + b"\x00\x00\x00\x01" + b"namespace") + struct.pack(">I", 0)
r = ssh_rt(c, sshsig)
check("ログイン以外の署名（SSHSIG）も、確認（ユーザー名なし）を通せば署名できる", r[0] == 14 and polk == [(SSH, "PT:2.sshname|a|b")])
c.close()
approve(False)
gate.parent_of = lambda pid: (999996, 1)
c = sshc()
n_up = len(ssh_up)
r = ssh_rt(c, sign_body(BLOB))
check("本人確認が通らなければ、署名は上流に届かない", r[0] == 5 and len(ssh_up) == n_up)
r = ssh_rt(c, b"\x0d\x00")
check("壊れた署名依頼は断る", r[0] == 5 and len(ssh_up) == n_up)
c.close()
gate.parent_of = orig_parent

# ===== 記録（journal）に、項目名などを書かない =====
leaks = [m for m in logs if "PT:" in m or "ENC(" in m or any(w in m for w in ("sshname", "pkname", "example.com", "site", "mykey"))]
check("gate の記録に、項目名・サイト名・秘密が一切含まれない", not leaks)
check("記録には、確認の許可・拒否が短い識別子つきで残る", any(m.startswith("許可: ") and "[" in m for m in logs) and any(m.startswith("拒否: ") for m in logs))
if leaks:
    print("漏れた記録:", leaks[:3])

print("結果:", "全部OK" if ok else "失敗あり")
shutil.rmtree(D, ignore_errors=True)
sys.exit(0 if ok else 1)
