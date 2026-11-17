#!/usr/bin/env python3
"""install/setup-bwvault.sh の安全確認の試験。

確かめること: 入れる前に差分を見せる／yes と入力しない限り何も入れない／/etc/pam.d/polkit-1 の確認は --yes でも省けない／
端末がなければ中止する／改ざんが --check の差分に出る。
root が要るスクリプトなので、試験用の複製だけ「root かどうか」の判定を外して動かす。確認の段階で全部止まる試験なので、
システムには何も書かない（誤って先へ進んでも、root でないので、書き込みの時点で失敗する）。
"""
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
T = tempfile.mkdtemp(prefix="bwvault-setup-test-")
for d in ("bin", "install", "pam", "polkit", "systemd"):
    shutil.copytree(os.path.join(ROOT, d), os.path.join(T, d))
SCRIPT = os.path.join(T, "install", "setup-bwvault.sh")
s = open(SCRIPT).read()
s2 = re.sub(r'\[ "\$\(id -u\)" = 0 \] && \[ -n "\$\{SUDO_USER:-\}" \] \|\|', "true ||", s, count=1)
assert s != s2, "root の判定の行が見つからない（スクリプトが変わった？ 試験を直すこと）"
open(SCRIPT, "w").write(s2)
# 改ざん: PAM を「誰でも通る」に、gate に1行
pam = os.path.join(T, "pam", "polkit-1")
orig = open(pam).read()                        # 先に読む（書き込み用に開くと、中身が消えるため）
tampered = orig.replace("auth    required                      pam_permit.so",
                        "auth    sufficient                    pam_permit.so\nauth    required                      pam_permit.so")
assert tampered != orig, "PAM の改ざんの置き換えが効いていない（pam/polkit-1 が変わった？ 試験を直すこと）"
open(pam, "w").write(tampered)
open(os.path.join(T, "bin", "bwvault-gate"), "a").write("# evil\n")

ok = True


def run(args, answers, tty=True):
    cmd = ["env", "SUDO_USER=" + os.environ.get("USER", "nobody"), "bash", SCRIPT, *args]
    if not tty:
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
        return r.stdout + r.stderr, r.returncode
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    out, i, deadline = "", 0, time.time() + 30
    status = None
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.3)
        if r:
            try:
                data = os.read(fd, 65536).decode(errors="replace")
            except OSError:          # 子が終わると、疑似端末の読み取りは EIO になる
                data = ""
            if data:
                out += data
                if out.rstrip().endswith("[yes/NO]") and i < len(answers):
                    os.write(fd, (answers[i] + "\n").encode())
                    out += f"\n<<< 送信: {answers[i]!r}\n"
                    i += 1
                continue
        done, st = os.waitpid(pid, os.WNOHANG)       # 子が終わっていれば、そこで止める（タイムアウトまで待たない）
        if done:
            status = st
            break
    if status is None:
        os.kill(pid, 9)
        _, status = os.waitpid(pid, 0)
        out += "\n（30 秒たっても終わらないので、打ち切りました）"
    return out, os.waitstatus_to_exitcode(status)


def check(title, out, code, want_code, must, mustnot=()):
    global ok
    good = code == want_code and all(m in out for m in must) and not any(m in out for m in mustnot)
    ok &= good
    print(("OK  " if good else "NG  ") + title + f"（終了コード {code}）")
    if not good:
        print(out[-500:])


o, c = run(["--check"], [], tty=False)
check("改ざん（PAM に pam_permit sufficient、gate に1行）が --check の差分に出て、終了コード 1",
      o, c, 1, ["変更  /etc/pam.d/polkit-1", "+auth    sufficient                    pam_permit.so", "変更  /usr/local/lib/bwvault/bwvault-gate", "+# evil"])
o, c = run([], ["no"])
check("最初の確認に no → 中止して、何も変更しない", o, c, 1, ["中止しました。何も変更していません"], ["書き換えます"])
o, c = run([], ["yes", "no"])
check("最初に yes でも、PAM の確認（別）が出る。そこで no → 中止", o, c, 1,
      ["/etc/pam.d/polkit-1 を書き換えます", "中止しました。何も変更していません"])
o, c = run(["--yes"], ["no"])
check("--yes でも、PAM の確認は省かれない（最初の確認は出ない）", o, c, 1,
      ["/etc/pam.d/polkit-1 を書き換えます", "中止しました"], ["差分を読んで、心当たり"])
o, c = run([], [], tty=False)
check("端末がない（自動実行）なら、確認できないので中止する", o, c, 1, ["対話の端末がないので、確認できません"])
o, c = run(["--yes"], [], tty=False)
check("--yes でも、端末がなければ PAM の確認はできず中止する", o, c, 1, ["対話の端末がないので、確認できません"])
for ans, name in (("", "空の入力（Enter だけ）"), ("YES", "YES（大文字）"), ("y", "y"), ("yes!", "yes!")):
    o, c = run([], [ans])
    check(f"{name} は yes ではない → 中止", o, c, 1, ["中止しました。何も変更していません"])
# read -r は前後の空白を取り除くので、"yes " は yes として受理される（害はない）。受理されても、PAM の確認は別に出る
o, c = run([], ["yes ", "no"])
check("yes（後ろに空白）は yes として受理されるが、PAM の確認は別に出て、no で中止する", o, c, 1,
      ["/etc/pam.d/polkit-1 を書き換えます", "中止しました。何も変更していません"])
o, c = run(["--bogus"], [], tty=False)
check("知らない引数は使い方を出して終了コード 2", o, c, 2, ["使い方"])

print("結果:", "全部OK" if ok else "失敗あり")
shutil.rmtree(T, ignore_errors=True)
sys.exit(0 if ok else 1)
