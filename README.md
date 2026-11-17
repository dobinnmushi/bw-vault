# bw-vault

[日本語](README.ja.md)

Keeps the key to your Bitwarden vault ([rbw](https://github.com/doy/rbw)) under a **separate user, `bwvault`**, and asks
**polkit — your fingerprint, then your password, like `sudo` —** before any secret leaves it.

## Status

**Experimental.** It was built and checked in the following setup only; nothing else has been tried.

- Ubuntu 26.04 (GNOME 50 / Wayland), one laptop with a fingerprint reader and a TPM2, **one user**.
- It installs things as root (`/etc/pam.d/polkit-1`, system services, a dedicated user). Read what it installs; the installer
  shows a diff and asks before it changes anything.
- It passes its automated tests (`tests/run.sh`) and an automated security review of the changes. **It has not been audited by
  an independent third party.**
- No compatibility promise yet (`docs/protocol.md` included).

## Three parts

One of three repositories that let you use Bitwarden on a Linux desktop (GNOME / Wayland) for typing passwords, passkeys and SSH.
bw-vault is the **authentication part**; the other two also work on their own.

| Repository | What it does | Without bw-vault |
|---|---|---|
| **bw-vault** (this) | Keeps the vault key under another user and asks polkit before any secret leaves it. Also an SSH agent | – |
| [bw-autotype](https://github.com/dobinnmushi/bw-autotype) | Types usernames, passwords and TOTP codes into any app with a hotkey; creates new logins | Works alone (checks your fingerprint itself) |
| [bw-passkey](https://github.com/dobinnmushi/bw-passkey) | A virtual FIDO2 security key that uses the passkeys in your vault | Works alone (checks your fingerprint itself) |

Used together, typing, passkeys and SSH **all go through the same gate and the same confirmation** (fingerprint, then password).
bw-autotype and bw-passkey use the gate automatically when its socket exists, and behave as before when it does not.
Install bw-vault first (see "Install"), then bw-autotype and bw-passkey (see their READMEs).
The protocol with the gate is in [`docs/protocol.md`](docs/protocol.md) (Japanese), so other clients can be written.

## Why

Once unlocked, rbw-agent keeps the vault key in memory and **answers "decrypt this" for any program running as your user**.
The fingerprint check on a hotkey (bw-autotype) only guards that screen; another program can still run `rbw get`.
Linux has no permission boundary between programs of the same user (file modes, socket modes and checks inside a program can all be
bypassed by the same user), so the key and the ability to decrypt are moved to **another user**, which demands authentication.

## What it protects, and what it does not

**Protects** (from programs running as your user that have not passed a confirmation):
- Item secrets: passwords, TOTP, notes, cards, SSH private keys, hidden fields, history, passkey private keys
- The list of item names, usernames, URLs, folder names and passkey sites
- The encrypted vault key and access token (so the master password cannot be brute-forced offline from a copy)
- The agent socket, which could decrypt, encrypt and stop the agent on request

**Does not protect:**
- root and anyone who can use `sudo`; kernel vulnerabilities; physical attacks (the sealed master password can be decrypted by root with `systemd-creds decrypt`)
- The moment you approve: the plaintext goes to the caller (the typing program). Keyloggers.
- You approving a prompt without thinking (the dialog shows **which item** and **which program** asks; you are expected to look).
  The same goes for the `yes` of the installer: read the diff and confirm there is nothing you do not recognize before you type it
- During the list approval window (20 seconds by default), every process of your user can see the list of names (not secrets)

## How it works

```
your user                                       bwvault (dedicated user, system services)
 rbw (wrapper) rofi-rbw bw-autotype bwv ──┐      ┌ bwvault-gate ── asks polkit ──→ your screen (fingerprint)
 bw-passkey  ssh / git ───────────────────┴socket→│   ├ list: returned after a confirmation (list)
                                                   │   ├ secrets: per item, after a confirmation (secret)
                                                   │   ├ writes: encrypted and sent after a confirmation (write)
                                                   │   └ SSH signatures: passed to the agent after a confirmation (ssh-sign)
                                                   └ rbw-agent (unmodified) ── vault key, token, database
```

- **bwvault-agent**: the stock rbw-agent, run as a dedicated user (`ProtectHome`, `ProtectProc`, `CapabilityBoundingSet=` and more;
  3.1 in `systemd-analyze security`). The binaries live in the root-owned `/usr/local/lib/bwvault/`.
- **bwvault-gate**: the only entrance your user can use (`/run/bwvault-gate/`). It speaks rbw's JSON-lines protocol and decides per request
  (3.3). The peer's pid and uid come from `SO_PEERCRED`, which the kernel provides.
- **Automatic unlock**: the master password is sealed with `systemd-creds` (TPM2 and the host key), and the gate has the agent unlock when it is used.
  `lock_timeout` is 300 seconds (it locks when unused). Unlocking itself reveals nothing, so it needs no confirmation.
- **Your side**: the `rbw` wrapper (`shim/rbw`) replaces `get`, `code` and `add` with `bwv`, and around `list` and `sync` it refreshes an encrypted copy of the
  items without the token and keys (`~/.cache/rbw-vault/`). The profile is `RBW_PROFILE=vault`.

### Confirmations

| polkit action | When | What the dialog shows | What the approval is bound to, and for how long |
|---|---|---|---|
| `…bwvault.list` | The list of item names etc., the list of passkeys, an item without its secrets (username and URIs only: typing or copying just the username) | The requester | **All of your user**, 20 seconds (separate processes fetch the list during one action) |
| `…bwvault.secret` | Fetching an item, a passkey's private key | The **item name** (for a passkey, the site and username) and the requester | Items: **parent process + item** (rofi-rbw starts `rbw get` and `rbw code` (TOTP) as separate processes one after another); passkeys: **process + passkey**; 10 seconds. A different item always asks again |
| `…bwvault.write` | Creating an item or a passkey | The kind and name of the new entry, and the requester | Process + name, 10 seconds |
| `…bwvault.ssh-sign` | An SSH signature | The key's item name and the username being logged in as | **Parent process + key**, 30 seconds (`git push` may start ssh several times; they are children of the same git) |

You get 5 fingerprint attempts, then the password (`pam/polkit-1`; sudo and login are not changed).
Binding approvals to an item is deliberate: the item name in the dialog lets you spot a request aimed at a different item.

## Install

Requirements: rbw 1.15.0 (`~/.local/bin/rbw` and `rbw-agent`, ELF binaries), polkit and fprintd (fingerprint), TPM2 and a systemd with `systemd-creds` and
`LoadCredentialEncrypted=` (tested with 259), `python3-gi`, `pinentry-curses`.

```sh
bash install/setup-bwvault.sh --check  # see what would be installed (no root)
sudo bash install/setup-bwvault.sh     # installs the bwvault user, services and polkit definitions; shows a diff and asks for yes
sudo bwvault-admin login               # log in to Bitwarden on the bwvault side (master password, two-step login)
sudo bwvault-admin sync
sudo bwvault-admin seal-master         # seal the master password with the TPM2 → from now on it unlocks automatically
install/install-user.sh                # your side: the rbw wrapper, bwv, SSH_AUTH_SOCK (no sudo). Log in again afterwards
```

If you use bw-autotype, set `[auth] method = "none"` in `~/.config/bw-autotype/config.toml` (the gate confirms for you; do not ask twice).
bw-passkey uses the gate automatically when its socket exists.

### Safety checks in the installer

`setup-bwvault.sh` copies files from your folder (which your user can modify) into sensitive system locations (including `/etc/pam.d/polkit-1`) as root.
So that you notice if a malicious program modified that folder beforehand:

- It first **copies the files to a root-owned temporary directory**, shows that copy, and installs only that copy (what you see is what gets installed).
- It shows the **diff** against the installed version (a SHA-256 for new files) and installs nothing unless you type `yes`.
- If `/etc/pam.d/polkit-1` changes, it asks a **separate question** interactively (`--yes` does not skip it; without a terminal it aborts).
- The rbw binaries are checked against recorded hashes (it asks if they differ).
- Tests: `tests/test_setup.py` (tampering shows up in the diff; the confirmations cannot be skipped).

## Daily use

| To | Run |
|---|---|
| See the state | `systemctl status bwvault-agent bwvault-gate`, `journalctl -u bwvault-gate` (the log holds no item names, only short ids like `[a1b2c3d4]`) |
| Lock, unlock or sync by hand | `sudo bwvault-admin lock` / `unlock` / `sync` |
| You changed the master password | Run `sudo bwvault-admin seal-master` again |
| Change the length of the confirmation windows | Put `BWVAULT_LIST_SECONDS`, `BWVAULT_GROUP_SECONDS` or `BWVAULT_SSH_GROUP_SECONDS` in `/etc/bwvault/gate.env`, then `sudo systemctl restart bwvault-gate` |
| The list is slow | The gate decrypts the list (`rbw list --raw`) and remembers it, so it is fast from the second time on. If it is slow, check with `systemctl status bwvault-gate` that the gate was not restarted (the first time after an update or reboot decrypts again) |
| You updated the gate | First `bash install/setup-bwvault.sh --check` (no root; only shows the diff against what is installed). Then `sudo bash install/setup-bwvault.sh` (shows the diff and what it will restart, and asks for `yes`; it restarts the gate only when the gate or its unit changed, and never restarts the agent, because that would lock it. It does not overwrite an installed rbw) |
| You updated rbw | Put the new `rbw` and `rbw-agent` in place with `sudo install -m 0755 … /usr/local/lib/bwvault/` |
| It no longer unlocks after a firmware update, etc. | `sudo bwvault-admin seal-master` (the seal is not bound to TPM PCRs) |

## Limits

- The stock `rbw get` is refused the secret fields (use `bwv get` and `bwv code`; the wrapper substitutes them). `--full`, `--field` and `--clipboard` are not supported.
- TOTP: base32 and `otpauth://` only (SHA1, SHA256, SHA512). Steam Guard (`steam://`) is not supported.
- `rbw edit`, `remove` and `search` do not work. `rbw add` creates login items only (SSH keys go through bw-autotype).
- Signing in with a passkey needs two confirmations: the list, then the key.
- The gate talks to Bitwarden's API directly (to create items and list passkeys).
- During the list approval window, every process of your user can see the list of names. A shorter window means more confirmations.
- It cannot stop a fake authentication dialog from getting you to type your password (as long as the fingerprint works, there is nothing to type).
- SSH signing was checked on a real machine only up to `ssh-keygen -Y sign`; logging in to a real server such as GitHub has not been checked.

## Tests

```sh
tests/run.sh      # uses a fake agent, a fake API and a fake polkit; needs neither sudo nor a real vault
```

They check the gate's promises (the confirmations above, how approvals are bound, unlocking, writes, SSH, and that no names are logged).
They are also checked to fail against deliberately broken gates (logging names, dropping the list confirmation, not binding approvals to an item).

## Layout

| | |
|---|---|
| `bin/bwvault-gate` | The gate (Python, standard library + Gio). A system service of `bwvault` |
| `bin/pinentry-bwvault` | Called by rbw-agent as its pinentry; returns the sealed master password |
| `bin/bwvault-admin` | `sudo bwvault-admin login / unlock / sync / seal-master / …` (rbw as `bwvault`) |
| `bin/bwv`, `bin/bwv-pull` | Your side: fetching items, codes, adding items, and refreshing the encrypted copy |
| `shim/rbw` | Your side: the wrapper to put at `~/.local/bin/rbw` |
| `systemd/` | `bwvault-agent.service`, `bwvault-gate.service`, `user/bwvault-ssh.service` |
| `polkit/`, `pam/` | The polkit action definitions (four), the PAM configuration for polkit |
| `install/` | `setup-bwvault.sh` (sudo), `install-user.sh` |
| `LICENSE` | MIT |
| `docs/` | Design decisions and lessons (`design.md`), the gate protocol (`protocol.md`), candidate issues and PRs for upstream (`upstream-candidates.md`). **In Japanese** |

## Uninstall

```sh
systemctl --user disable --now bwvault-ssh.service && rm ~/.config/systemd/user/bwvault-ssh.service
mv ~/.local/bin/rbw.bak-YYYYMMDD ~/.local/bin/rbw          # back to the old rbw (replaces the wrapper's link)
sudo systemctl disable --now bwvault-gate bwvault-agent
sudo rm -r /etc/systemd/system/bwvault-*.service* /etc/bwvault /usr/local/lib/bwvault /usr/local/sbin/bwvault-admin \
           /usr/share/polkit-1/actions/io.github.dobinnmushi.bwvault.policy /etc/pam.d/polkit-1
sudo userdel bwvault && sudo rm -r /var/lib/bwvault          # this also deletes the vault data (token, encrypted database)
```

Afterwards, run `rbw login` again with the old rbw.

## Reporting vulnerabilities

If you think you found a vulnerability, please use the **Security** tab → "Report a vulnerability" (private reporting) on GitHub instead of a public issue.

## License and credits

[MIT](LICENSE). It uses rbw unmodified (rbw's own license applies). The gate learned from rbw's protocol (`src/protocol.rs`) and from the
idea of re-confirming per item on the agent side (the comment in `state.rs`).
