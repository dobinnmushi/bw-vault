#!/usr/bin/env python3
"""install/setup-bwvault.sh の安全確認と、再起動の判断の試験。

確かめること: 入れる前に差分を見せる／yes と入力しない限り何も入れない／/etc/pam.d/polkit-1 の確認は --yes でも省けない／
端末がなければ中止する／改ざんが --check の差分に出る／gate が変わったときだけ gate を再起動する（agent は再起動しない）。

root が要り、システムの置き場（/usr/local/lib/bwvault、/etc/pam.d など）と比べるスクリプトなので、試験用の複製だけ
「root かどうかの判定」を外し、置き場を一時ディレクトリの偽のルートに付け替えて動かす。システムには何も書かない
（確認の段階で止まる試験だけ。誤って先へ進んでも、偽のルートの外へは書けず、root でもないので失敗する）。
実機の状態（配備済みかどうか）には左右されない。
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
FAKE = os.path.join(T, "root")          # 偽の「システム」。ここにリポジトリの版を並べておく（変更なしの基準）
DIRS = ("bin", "install", "pam", "polkit", "systemd")
POLICY = "polkit/io.github.dobinnmushi.bwvault.policy"
# リポジトリ内の相対パス → システムの置き場所
PLACES = {
    "bin/bwvault-admin": "/usr/local/sbin/bwvault-admin",
    "bin/bwvault-gate": "/usr/local/lib/bwvault/bwvault-gate",
    "bin/pinentry-bwvault": "/usr/local/lib/bwvault/pinentry-bwvault",
    POLICY: "/usr/share/polkit-1/actions/io.github.dobinnmushi.bwvault.policy",
    "pam/polkit-1": "/etc/pam.d/polkit-1",
    "systemd/bwvault-agent.service": "/etc/systemd/system/bwvault-agent.service",
    "systemd/bwvault-gate.service": "/etc/systemd/system/bwvault-gate.service",
}
for rel, place in PLACES.items():
    dest = FAKE + place
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy(os.path.join(ROOT, rel), dest)
for name in ("rbw", "rbw-agent"):            # rbw の実体は、ELF の印だけある偽物（置き済みとして扱われる）
    shutil.copy("/bin/true", FAKE + "/usr/local/lib/bwvault/" + name)


def make_script(variant, mutate=None):
    """リポジトリの複製（variant）を作り、mutate で書き換え、スクリプトの root 判定と置き場を、偽のルートに付け替える"""
    tree = os.path.join(T, variant)
    for d in DIRS:
        shutil.copytree(os.path.join(ROOT, d), os.path.join(tree, d))
    if mutate:
        mutate(tree)
    path = os.path.join(tree, "install", "setup-bwvault.sh")
    s = open(path).read()
    s2 = re.sub(r'\[ "\$\(id -u\)" = 0 \] && \[ -n "\$\{SUDO_USER:-\}" \] \|\|', "true ||", s, count=1)
    assert s != s2, "root の判定の行が見つからない（スクリプトが変わった？ 試験を直すこと）"
    s = s2
    for old in ("/usr/local/sbin/", "/usr/share/polkit-1/", "/etc/pam.d/", "/etc/systemd/system/"):
        assert old in s, old
        s = s.replace(old, FAKE + old)
    s3 = s.replace("LIB=/usr/local/lib/bwvault", "LIB=" + FAKE + "/usr/local/lib/bwvault")
    assert s3 != s
    open(path, "w").write(s3)
    return path


def edit(rel, fn):
    def m(tree):
        p = os.path.join(tree, rel)
        old = open(p).read()
        new = fn(old)
        assert new != old, f"{rel} の書き換えが効いていない"
        open(p, "w").write(new)
    return m


def both(*ms):
    return lambda tree: [m(tree) for m in ms]


PAM_TAMPER = edit("pam/polkit-1", lambda s: s.replace("auth    required                      pam_permit.so",
                                                      "auth    sufficient                    pam_permit.so\nauth    required                      pam_permit.so"))
GATE_TAMPER = edit("bin/bwvault-gate", lambda s: s + "# evil\n")

ok = True


def run(script, args, answers, tty=True):
    cmd = ["env", "SUDO_USER=" + os.environ.get("USER", "nobody"), "bash", script, *args]
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
        print(out[-600:])


RESTART_GATE = "bwvault-gate を再起動します"
NO_RESTART = "サービスの再起動は要りません"
AGENT_NOTE = "bwvault-agent の unit が変わります"

# ---- 差分の表示と、再起動の判断（--check。root も端末も要らない）----
S = make_script("same")
o, c = run(S, ["--check"], [], tty=False)
check("変更がなければ、「変更はありません。」で終了コード 0", o, c, 0, ["変更はありません。"], [RESTART_GATE, "== 反映のしかた =="])

S = make_script("tamper", both(PAM_TAMPER, GATE_TAMPER))
o, c = run(S, ["--check"], [], tty=False)
check("改ざん（PAM に pam_permit sufficient、gate に1行）が、差分に出て、終了コード 1", o, c, 1,
      ["変更  " + FAKE + "/etc/pam.d/polkit-1", "+auth    sufficient                    pam_permit.so", "変更  " + FAKE + "/usr/local/lib/bwvault/bwvault-gate", "+# evil"])
check("gate が変わるときは、gate を再起動すると、先に表示する（agent は再起動しない）", o, c, 1, [RESTART_GATE, "解錠は外れません"], [AGENT_NOTE])

S = make_script("admin", edit("bin/bwvault-admin", lambda s: s + "# changed\n"))
o, c = run(S, ["--check"], [], tty=False)
check("bwvault-admin だけが変わるときは、サービスの再起動は要らない（gate を再起動しない）", o, c, 1, [NO_RESTART, "変更  " + FAKE + "/usr/local/sbin/bwvault-admin"], [RESTART_GATE, AGENT_NOTE])

S = make_script("policy", edit(POLICY, lambda s: s + "<!-- changed -->\n"))
o, c = run(S, ["--check"], [], tty=False)
check("polkit の定義だけが変わるときも、サービスの再起動は要らない（polkit が自動で読み直す）", o, c, 1, [NO_RESTART], [RESTART_GATE])

S = make_script("gateunit", edit("systemd/bwvault-gate.service", lambda s: s + "# changed\n"))
o, c = run(S, ["--check"], [], tty=False)
check("gate の unit が変わるときは、gate を再起動する", o, c, 1, [RESTART_GATE], [AGENT_NOTE])

S = make_script("agentunit", edit("systemd/bwvault-agent.service", lambda s: s + "# changed\n"))
o, c = run(S, ["--check"], [], tty=False)
check("agent の unit が変わるときは、再起動が要ると断る（解錠が外れるので、スクリプトは再起動しない）", o, c, 1,
      [AGENT_NOTE, "このスクリプトは再起動しません"], [RESTART_GATE])

# ---- 確認の動き（改ざんした複製で）----
S = make_script("tamper2", both(PAM_TAMPER, GATE_TAMPER))
o, c = run(S, [], ["no"])
check("最初の確認に no → 中止して、何も変更しない", o, c, 1, ["中止しました。何も変更していません"], ["書き換えます"])
o, c = run(S, [], ["yes", "no"])
check("最初に yes でも、PAM の確認（別）が出る。そこで no → 中止", o, c, 1,
      ["/etc/pam.d/polkit-1 を書き換えます", "中止しました。何も変更していません"])
o, c = run(S, ["--yes"], ["no"])
check("--yes でも、PAM の確認は省かれない（最初の確認は出ない）", o, c, 1,
      ["/etc/pam.d/polkit-1 を書き換えます", "中止しました"], ["差分を読んで、心当たり"])
o, c = run(S, [], [], tty=False)
check("端末がない（自動実行）なら、確認できないので中止する", o, c, 1, ["対話の端末がないので、確認できません"])
o, c = run(S, ["--yes"], [], tty=False)
check("--yes でも、端末がなければ PAM の確認はできず中止する", o, c, 1, ["対話の端末がないので、確認できません"])
for ans, name in (("", "空の入力（Enter だけ）"), ("YES", "YES（大文字）"), ("y", "y"), ("yes!", "yes!")):
    o, c = run(S, [], [ans])
    check(f"{name} は yes ではない → 中止", o, c, 1, ["中止しました。何も変更していません"])
# read -r は前後の空白を取り除くので、"yes " は yes として受理される（害はない）。受理されても、PAM の確認は別に出る
o, c = run(S, [], ["yes ", "no"])
check("yes（後ろに空白）は yes として受理されるが、PAM の確認は別に出て、no で中止する", o, c, 1,
      ["/etc/pam.d/polkit-1 を書き換えます", "中止しました。何も変更していません"])
o, c = run(S, ["--bogus"], [], tty=False)
check("知らない引数は使い方を出して終了コード 2", o, c, 2, ["使い方"])

# root で動くシェルスクリプトの python3 は、-I（いま居るフォルダ・環境変数からモジュールを読まない）で動かす。
# setup-bwvault.sh は、あなたのリポジトリの中で sudo 実行されるので、-I がないと、そこに置かれた json.py などが root で動く
bad = []
for rel in ("install/setup-bwvault.sh", "bin/bwvault-admin"):
    with open(os.path.join(ROOT, rel)) as f:
        for n, line in enumerate(f, 1):
            if re.search(r"\bpython3?\b(?!\s+-I\b)", line.split("#", 1)[0]):
                bad.append(f"{rel}:{n}")
check(f"root で動くスクリプトの python3 は、すべて -I つき（違反: {bad}）", "", 0 if not bad else 1, 0, [])

print("結果:", "全部OK" if ok else "失敗あり")
shutil.rmtree(T, ignore_errors=True)
sys.exit(0 if ok else 1)
