#!/usr/bin/env python3
"""pinentry-bwvault の試験。rbw の pinentry.rs の read_password と同じ読み方で、特殊文字を含むパスワードが正しく戻るかを見る。"""
import os
import subprocess
import sys
import tempfile

SHIM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "pinentry-bwvault")


def rbw_read_password(ncommands, out):
    """rbw の read_password（OK を数え、D の行を % 復号する）と同じ"""
    for line in out.split(b"\n"):
        if line.startswith(b"OK"):
            if ncommands == 1:
                return b""
            ncommands -= 1
        elif line.startswith(b"D "):
            data, res, i = line[2:], bytearray(), 0
            while i < len(data):
                c = data[i]
                if c == 0x25 and i + 2 < len(data):
                    try:
                        c = int(data[i + 1:i + 3].decode(), 16)
                        i += 2
                    except ValueError:
                        pass
                res.append(c)
                i += 1
            return bytes(res)
        elif line.startswith(b"ERR "):
            return "ERR:" + line.decode()
        elif line == b"":
            continue
        else:
            raise RuntimeError("parse " + repr(line))


def run(pw, with_error=False, cred=True):
    d = tempfile.mkdtemp()
    if cred:
        open(os.path.join(d, "bwvault-master"), "wb").write(pw)
    cmds = [b"SETTITLE rbw", b"SETPROMPT Master Password", b"SETDESC Unlock the local database for 'rbw'"]
    if with_error:
        cmds.append(b"SETERROR bad (attempt 2/3)")
    cmds.append(b"GETPIN")
    r = subprocess.run([SHIM, "--timeout", "0"], input=b"\n".join(cmds) + b"\n", capture_output=True,
                       env={"CREDENTIALS_DIRECTORY": d, "PATH": os.environ["PATH"]})
    return rbw_read_password(1 + len(cmds), r.stdout), r


ok = True
pws = [b"simple", "日本語のパスワード🔑".encode(), b"100%25 sure", b"a%b%0Ac", b"with\nnewline", b"cr\rlf", b"trailing space ",
       b"%", b"x" * 200, b"quote'\"back\\slash"]
for pw in pws:
    for we in (False, True):
        got, _ = run(pw, we)
        if got != pw:
            ok = False
            print("NG ", pw, we, got)
print(("OK  " if ok else "NG  ") + f"特殊文字を含むパスワード {len(pws) * 2} 通りが、そのまま戻る")
got, r = run(b"", cred=False)
good = isinstance(got, str) and got.startswith("ERR:") and r.returncode == 1
ok &= good
print(("OK  " if good else "NG  ") + "資格情報がなければ ERR を返して失敗する:", got)
print("結果:", "全部OK" if ok else "失敗あり")
sys.exit(0 if ok else 1)
