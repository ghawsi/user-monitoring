# User Session Monitor

**Per-login session and command recording for Ubuntu Server**

| Item | Value |
|---|---|
| Version | 1.0 (2026-11-09) |
| Platform | Ubuntu Server, LTS (Long-Term Support) release 20.04 or later |
| Runtime | Python 3.8+, Bash 4.4+, auditd (Linux Audit Daemon) |
| Status | Tested in a simulated environment and confirmed working on a live server (2026-11-09) |

---

## Abstract

User Session Monitor writes **one plain-text file per login**. Each file records who logged in, when, and from which IP (Internet Protocol) address. It also records every command line the user typed, including shell built-ins such as `echo` and `cd`, every program that was actually started, and the logout time.

The Linux kernel audit subsystem does the recording. A small Python daemon, readable only by root and run by systemd, turns the raw audit records into readable files. Ordinary users cannot read, edit or stop the recording.

---

## Table of Contents

1. [Example Output](#1-example-output)
2. [Architecture](#2-architecture)
3. [Requirements](#3-requirements)
4. [Installation](#4-installation)
5. [Verification](#5-verification)
6. [Daily Use](#6-daily-use)
7. [Maintenance](#7-maintenance)
8. [Troubleshooting](#8-troubleshooting)
9. [Known Limitations](#9-known-limitations)
10. [Security and Compliance Notes](#10-security-and-compliance-notes)
11. [Uninstallation](#11-uninstallation)
12. [Concepts for Further Study](#12-concepts-for-further-study)

---

## 1. Example Output

File: `/var/log/user_sessions/2026-11-09_11-43-20_bob_session42.txt`

```text
User    : bob
Login   : 2026-11-09 11:43:20
From    : 203.0.113.5 (ssh)
------------------------------------------------------------
2026-11-09 11:43:20  bob          dircolors -b
2026-11-09 11:43:21  bob        $ echo what\'s up!
2026-11-09 11:43:22  bob        $ ls -la
2026-11-09 11:43:23  bob        $ cd /var/www
2026-11-09 11:43:24  bob        $ ls | grep conf
2026-11-09 11:43:24  bob          ls
2026-11-09 11:43:24  bob          grep conf
2026-11-09 11:43:25  bob        $ sudo apt update
2026-11-09 11:43:25  root         apt update
------------------------------------------------------------
Logout  : 2026-11-09 11:43:29
```

| Element | Meaning |
|---|---|
| File name | `<login date>_<login time>_<user>_session<audit session ID>.txt` |
| `$ command` | A line the user typed at the bash prompt |
| `  command` (indented, no `$`) | A program that was started: parts of a pipeline, commands run through `sudo`, programs started by login scripts. When a program line would repeat the typed line exactly, it is left out. |
| Second column | The account the command ran as (for example `root` after `sudo`) |

---

## 2. Architecture

```text
   User types a command at the bash prompt
          |
          |-- /etc/user-monitor.bash (bash hook) -- reports the typed line --.
          |                                                                   |
          '-- kernel starts programs -- audit rule (execve) ------------------|
                                                                              v
                                              /var/log/audit/audit.log   (auditd)
                                                                              |
                        user-monitor.service --> /usr/local/bin/user_monitor.py
                                                                              v
                                 /var/log/user_sessions/<date>_<time>_<user>_session<N>.txt
```

### 2.1 Components

| # | Component | Path | Owner, Mode | Role |
|---|---|---|---|---|
| 1 | Audit rule | `/etc/audit/rules.d/user-monitor.rules` | root:root, 0640 | Tells the kernel to record every program started inside a login session |
| 2 | Daemon | `/usr/local/bin/user_monitor.py` | root:root, 0700 | Reads the audit log and writes one file per login |
| 3 | Service | `/etc/systemd/system/user-monitor.service` | root:root, 0644 | Runs the daemon in the background and restarts it 5 s after any failure |
| 4 | Bash hook | `/etc/user-monitor.bash`, plus one line in `/etc/bash.bashrc` | root:root, 0644 | Reports each typed command line, including shell built-ins |
| 5 | Output | `/var/log/user_sessions/` | root:root, 0700 (files 0600) | One `.txt` file per login |
| 6 | Cleanup (optional) | `/etc/cron.daily/user-monitor-cleanup` | root:root, 0755 | Deletes session files older than 365 days |

### 2.2 How Logins Are Identified

At login, the PAM (Pluggable Authentication Modules) module `pam_loginuid` gives the login a kernel **audit session ID**. Every process started in that login inherits it, including processes under `sudo` and `su`, and users cannot change it.

The daemon opens a file when auditd logs a `USER_START` event from `sshd` or `login`. It closes the file on the matching `USER_END` event. Logins created by `sudo`, `su` or `cron` do not get their own file.

### 2.3 How Shell Built-ins Are Captured

Built-ins such as `echo`, `cd` and `export` run inside the shell and start no program, so the kernel cannot see them.

The bash hook uses the `PS0` prompt, which bash expands just before it runs each command. The hook calls `/usr/bin/true user-monitor-typed "<typed line>"`. The kernel records that call against the user's session, and the daemon recognises the marker `user-monitor-typed` and writes the `$` line. The hook variables and functions are `readonly`, so users cannot switch the hook off within bash.

---

## 3. Requirements

| Requirement | Check |
|---|---|
| Ubuntu Server with `sudo` access | `sudo -v` |
| Python 3.8 or later (preinstalled on Ubuntu) | `python3 --version` |
| Bash 4.4 or later (for `PS0`) | `bash --version` |
| auditd | Installed in step 4.1 |

---

## 4. Installation

Paste each block into a terminal on the server, in order. **Every file is written directly by the commands below, so no download is needed.** Each file is first created empty with the correct owner and mode, then filled.

> Alternative: if you have the project folder (`user-session-monitor/`), you can run `sudo install -o root -g root -m <mode> <file> <target>` for each file in the table in section 2.1 instead. Run `ls` first to check the exact file names; downloads are sometimes renamed.

### 4.1 Install auditd and the Audit Rule

```bash
sudo apt install -y auditd

sudo install -o root -g root -m 0640 /dev/null /etc/audit/rules.d/user-monitor.rules
sudo tee /etc/audit/rules.d/user-monitor.rules >/dev/null <<'RULESEOF'
## Record every program started inside a login session (auid is set at login;
## 4294967295 means "not set", i.e. system services, which are ignored).
-a always,exit -F arch=b64 -S execve -F auid!=4294967295 -k usercmd
-a always,exit -F arch=b32 -S execve -F auid!=4294967295 -k usercmd
RULESEOF

sudo augenrules --load
sudo auditctl -l        # must show two lines ending in: -F key=usercmd
```

### 4.2 Install the Daemon

```bash
sudo install -o root -g root -m 0700 /dev/null /usr/local/bin/user_monitor.py
sudo tee /usr/local/bin/user_monitor.py >/dev/null <<'PYEOF'
#!/usr/bin/python3
"""
user_monitor.py - one .txt file per login: who, when, from where, and every
command the user ran until logout.

Sources (both via the kernel audit log /var/log/audit/audit.log, auditd rules
in /etc/audit/rules.d/user-monitor.rules):
  "$ ..." lines  : what the user typed at the bash prompt, incl. built-ins
                   such as echo/cd (reported by /etc/user-monitor.bash)
  "  ..." lines  : programs actually started (cannot be switched off by users)
Output: /var/log/user_sessions/<date>_<time>_<user>_session<N>.txt
"""

import os
import pwd
import re
import shlex
import signal
import sys
import time

AUDIT_LOG = "/var/log/audit/audit.log"
SESSION_DIR = "/var/log/user_sessions"
LOGIN_PROGRAMS = {"sshd", "sshd-session", "login"}   # what counts as a login
MARKER = "user-monitor-typed"                         # set by /etc/user-monitor.bash

STAMP = re.compile(r"msg=audit\((\d+)\.\d+:(\d+)\)")
FIELD = re.compile(r"(\w+)=(\"[^\"]*\"|[^\s']+)")
ARG = re.compile(r" a(\d+)(?:\[\d+\])?=(\"[^\"]*\"|\S+)")
LINE = "-" * 60 + "\n"

sessions = {}   # audit session id -> {"path": ..., "header": ...}
pending = {}    # event serial -> (session id, uid) taken from the SYSCALL record
running = True


def decode(value):
    """auditd writes normal values in quotes and unusual ones as hex."""
    if value.startswith('"'):
        return value[1:-1]
    try:
        return bytes.fromhex(value).decode("utf-8", "replace")
    except ValueError:
        return value


def fields(line):
    return dict(FIELD.findall(line.split("\x1d")[0]))   # drop auditd's appended names


def stamp(epoch, fmt="%Y-%m-%d %H:%M:%S"):
    return time.strftime(fmt, time.localtime(epoch))


def username(uid):
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, TypeError, ValueError):
        return str(uid)


def write(session, text):
    """Append to the session file; the header goes in when the file is created."""
    new = not os.path.exists(session["path"])
    with open(session["path"], "a", encoding="utf-8") as fh:
        fh.write((session["header"] if new else "") + text)


def handle(line, live):
    match = STAMP.search(line)
    if not match:
        return
    when, serial = float(match.group(1)), match.group(2)

    if line.startswith("type=SYSCALL") and 'key="usercmd"' in line:
        f = fields(line)
        pending[serial] = (f.get("ses"), f.get("uid"))

    elif line.startswith("type=EXECVE"):
        ses, uid = pending.pop(serial, (None, None))
        if live and ses in sessions:
            args = {}
            for idx, val in ARG.findall(line):
                args[int(idx)] = args.get(int(idx), "") + decode(val)
            argv = [args[i] for i in sorted(args)]
            session = sessions[ses]
            if argv[1:2] == [MARKER]:                    # a line typed at the prompt
                typed = re.sub(r"^\s*\d+\*?\s+", "", " ".join(argv[2:])).strip()
                if typed:
                    session["last"] = typed
                    write(session, "%s  %-10s $ %s\n" % (stamp(when), username(uid), typed))
            else:                                        # a program that was started
                command = shlex.join(argv)
                if command != session.pop("last", None):  # skip exact repeat of typed line
                    write(session, "%s  %-10s   %s\n" % (stamp(when), username(uid), command))

    elif line.startswith(("type=USER_START", "type=USER_END")) and "res=success" in line:
        f = fields(line)
        if os.path.basename(decode(f.get("exe", '""'))) not in LOGIN_PROGRAMS:
            return                                   # ignore sudo, su, cron, ...
        ses = f.get("ses")
        if line.startswith("type=USER_START"):
            user = decode(f.get("acct", '"unknown"'))
            name = "%s_%s_session%s.txt" % (stamp(when, "%Y-%m-%d_%H-%M-%S"),
                                            re.sub(r"[^A-Za-z0-9._-]", "_", user), ses)
            header = "User    : %s\nLogin   : %s\nFrom    : %s (%s)\n%s" % (
                user, stamp(when), f.get("addr", "?"), f.get("terminal", "?"), LINE)
            sessions[ses] = {"path": os.path.join(SESSION_DIR, name), "header": header}
            if live:
                write(sessions[ses], "")
        elif ses in sessions:
            session = sessions.pop(ses)
            if live:
                write(session, "%sLogout  : %s\n" % (LINE, stamp(when)))

    if len(pending) > 1000:                          # safety valve
        pending.clear()


def safe_handle(line, live):
    try:
        handle(line, live)
    except Exception as exc:                         # never die on one odd line
        print("skipped line (%s): %.200s" % (exc, line), file=sys.stderr)


def stop(_signum, _frame):
    global running
    running = False


def main():
    os.umask(0o077)                                  # files 0600, folder 0700: root only
    os.makedirs(SESSION_DIR, mode=0o700, exist_ok=True)
    signal.signal(signal.SIGTERM, stop)

    # After a restart: re-learn which logins are still open (nothing is written).
    try:
        with open(AUDIT_LOG + ".1", encoding="utf-8", errors="replace") as old:
            for line in old:
                safe_handle(line, live=False)
    except FileNotFoundError:
        pass

    log = open(AUDIT_LOG, encoding="utf-8", errors="replace")
    live, partial = False, ""
    while running:
        line = log.readline()
        if line:
            partial += line
            if partial.endswith("\n"):
                safe_handle(partial, live)
                partial = ""
            continue
        live = True                                  # caught up: write from now on
        try:
            rotated = os.stat(AUDIT_LOG).st_ino != os.fstat(log.fileno()).st_ino
        except FileNotFoundError:
            rotated = False
        if rotated:                                  # auditd started a new file
            for line in (partial + log.read()).splitlines(True):
                safe_handle(line, live)
            log.close()
            log = open(AUDIT_LOG, encoding="utf-8", errors="replace")
            partial = ""
            continue
        time.sleep(1)
    log.close()


if __name__ == "__main__":
    main()
PYEOF
```

### 4.3 Install the systemd Service

```bash
sudo install -o root -g root -m 0644 /dev/null /etc/systemd/system/user-monitor.service
sudo tee /etc/systemd/system/user-monitor.service >/dev/null <<'UNITEOF'
[Unit]
Description=Per-login session and command logger
After=network.target auditd.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/user_monitor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF
```

### 4.4 Install the Bash Hook

```bash
sudo install -o root -g root -m 0644 /dev/null /etc/user-monitor.bash
sudo tee /etc/user-monitor.bash >/dev/null <<'BASHEOF'
# /etc/user-monitor.bash - sourced from /etc/bash.bashrc (interactive bash only).
# Reports every command line typed at the prompt, including shell built-ins
# such as echo or cd, by starting /usr/bin/true with the line as argument;
# auditd records that call together with the user's login session.
if [ -n "${BASH_VERSION:-}" ] && [ -z "${__um_hooked:-}" ]; then
    __um_typed() { /usr/bin/true user-monitor-typed "$(HISTTIMEFORMAT= builtin history 1)"; }
    __um_keep()  { HISTCONTROL=; HISTIGNORE=; set -o history; }
    readonly -f __um_typed __um_keep
    readonly PS0='$(__um_typed)'
    readonly PROMPT_COMMAND="__um_keep${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
    readonly __um_hooked=1
fi
BASHEOF

grep -q user-monitor.bash /etc/bash.bashrc || \
  echo '[ -r /etc/user-monitor.bash ] && . /etc/user-monitor.bash' | sudo tee -a /etc/bash.bashrc >/dev/null
```

### 4.5 Start the Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now user-monitor
systemctl status user-monitor --no-pager
```

### 4.6 Optional: Automatic Cleanup After 365 Days

```bash
sudo install -o root -g root -m 0755 /dev/null /etc/cron.daily/user-monitor-cleanup
sudo tee /etc/cron.daily/user-monitor-cleanup >/dev/null <<'CLEANEOF'
#!/bin/sh
# /etc/cron.daily/user-monitor-cleanup - delete session files older than 365 days.
find /var/log/user_sessions -type f -name '*.txt' -mtime +365 -delete
CLEANEOF
```

---

## 5. Verification

### 5.1 Component Checks

```bash
systemctl is-active user-monitor                      # active
sudo auditctl -l | grep usercmd                       # two rule lines
grep user-monitor.bash /etc/bash.bashrc               # one source line
sudo stat -c '%U:%G %a %n' /usr/local/bin/user_monitor.py \
  /etc/systemd/system/user-monitor.service /etc/user-monitor.bash
```

Expected modes: `root:root 700`, `root:root 644`, `root:root 644`.

### 5.2 End-to-End Test

1. **Log out, then open a new SSH (Secure Shell) login.** Logins that were already open before installation are not tracked.
2. Type a few commands, for example `echo hello`, `ls -la`, `sudo whoami`.
3. Log out.
4. On the server, show the newest session file:

```bash
sudo ls -lt /var/log/user_sessions/
sudo sh -c 'cat "$(ls -t /var/log/user_sessions/*.txt | head -n 1)"'
```

---

## 6. Daily Use

The folder `/var/log/user_sessions/` is readable only by root. Commands that use a `*` wildcard must therefore run inside `sudo sh -c '...'`. Otherwise your own (non-root) shell tries to expand the `*` and fails.

```bash
# List all logins, newest first
sudo ls -lt /var/log/user_sessions/

# Show the newest login
sudo sh -c 'cat "$(ls -t /var/log/user_sessions/*.txt | head -n 1)"'

# All logins of one user (here: bob)
sudo ls /var/log/user_sessions/ | grep _bob_

# Find the logins in which a command was used
sudo grep -rl "rm -rf" /var/log/user_sessions/

# Show matching lines together with their file names
sudo grep -r "systemctl" /var/log/user_sessions/

# Follow one login live (replace <file>)
sudo tail -f /var/log/user_sessions/<file>.txt

# Service log
sudo journalctl -u user-monitor -n 50 --no-pager
```

---

## 7. Maintenance

### 7.1 Updating the Daemon

Re-run step 4.2 with the new code, then run:

```bash
sudo systemctl restart user-monitor
```

### 7.2 Retention

Session files are never deleted automatically unless step 4.6 is installed. A retention of 365 days matches common 12-month audit-log rules, for example PCI DSS (Payment Card Industry Data Security Standard) requirement 10.5.1. Set the period your own policy requires.

### 7.3 Audit Log Size

Recording every program start makes `/var/log/audit/audit.log` grow faster. auditd rotates the file itself, and the daemon follows rotations automatically. Check the size limits with:

```bash
grep -E '^(max_log_file|num_logs|max_log_file_action)' /etc/audit/auditd.conf
```

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Failed to enable unit: Unit file user-monitor.service does not exist.` | The service file was never written to `/etc/systemd/system/` | Re-run step 4.3, then 4.5 |
| The file shows login and logout but **no commands** | Audit rule not loaded | `sudo auditctl -l`; re-run step 4.1 |
| `auditctl -l` stays empty; `sudo auditctl -s` shows `enabled 2` | Audit rules are locked until reboot | `sudo reboot` (the rule loads at boot) |
| Programs (`ls`) are recorded, but not `echo` or `cd` | Bash hook not active | Check `grep user-monitor.bash /etc/bash.bashrc`; re-run step 4.4; log in again |
| No file at all for a login | Login opened before installation, or not through `sshd` or `login` | Log in again |
| `bash: PS0: readonly variable` (or `PROMPT_COMMAND`) at login | The user's `~/.bashrc` tries to set that variable | Remove that line from the user's `~/.bashrc` |
| Service keeps restarting | See its log: `sudo journalctl -u user-monitor -n 50` | Most often auditd is missing, so `/var/log/audit/audit.log` does not exist: re-run step 4.1 |
| `cat: '/var/log/user_sessions/*.txt': No such file or directory` | The `*` was expanded by a non-root shell | Use `sudo sh -c '...'` (see section 6) |

---

## 9. Known Limitations

1. **Typed lines (`$`) come from bash only.** A user who deliberately starts another shell (`sh`, `zsh`) produces no `$` lines there. Programs started from that shell are still recorded, because that part comes from the kernel and cannot be switched off by users.
2. **Login noise.** Login scripts start a few programs (for example `dircolors`). These appear as indented lines without `$`.
3. **History settings are overridden.** To capture every line, the hook clears `HISTCONTROL` and `HISTIGNORE` at each prompt. Users' bash history therefore also keeps duplicate commands and commands typed with a leading space.
4. **Non-interactive logins.** `ssh host 'command'`, SFTP (SSH File Transfer Protocol) and SCP (Secure Copy) logins get a file with indented program lines only, because no prompt is involved.
5. **Restart gap.** If the daemon crashes, systemd restarts it after 5 seconds. Logins that are still open are picked up again, but commands run during those seconds are not written.
6. **Logins open before installation** are not tracked. Log in again.
7. **Self-reported lines.** A user can add a fake `$` line to **their own** file by running the marker command by hand. The command they typed to do so is recorded too, so this is visible.

---

## 10. Security and Compliance Notes

- **Protection against ordinary users.** They cannot read the session files (0600 in a 0700 folder), change the daemon (0700, root), stop the service (that requires root), or remove the kernel audit rule.
- **Root and sudoers.** Users with root or `sudo` rights can stop or change anything on the server. If you need tamper-evident records, also forward the logs to a separate server.
- **Data protection.** Session files contain personal data (user names, IP addresses, activity), which falls under the GDPR (General Data Protection Regulation) in the EU (European Union). In German companies with a works council, technical systems that can monitor employees are subject to co-determination under § 87 (1) No. 6 BetrVG (Betriebsverfassungsgesetz, Works Constitution Act). Inform users, for example with an SSH login banner, and define a retention period. *This is not legal advice; confirm with your data protection officer or legal counsel.*

---

## 11. Uninstallation

```bash
sudo systemctl disable --now user-monitor
sudo rm -f /etc/systemd/system/user-monitor.service /usr/local/bin/user_monitor.py \
           /etc/audit/rules.d/user-monitor.rules /etc/user-monitor.bash \
           /etc/cron.daily/user-monitor-cleanup
sudo sed -i '\#/etc/user-monitor.bash#d' /etc/bash.bashrc
sudo systemctl daemon-reload
sudo augenrules --load
# Optional, deletes all recorded sessions:
# sudo rm -r /var/log/user_sessions
```

---

## 12. Concepts for Further Study

| Concept | Where it is used here |
|---|---|
| Linux Audit framework (`auditd`, `auditctl`, `ausearch`, audit rules) | Recording program starts and login events |
| Audit session ID and login UID (User Identifier), `pam_loginuid` | Linking every command to its login |
| The `execve` system call | The event recorded for every program start |
| Shell built-ins vs. external commands | Why `echo` needs the bash hook |
| Bash `PS0`, `PROMPT_COMMAND`, `readonly` | The typed-command hook |
| systemd service units (`Restart=always`, `RestartSec=`) | Self-healing background service |
| Log rotation and inodes | How the daemon follows `audit.log` after auditd rotates it |
| Heredocs with a quoted delimiter (`<<'EOF'`) | Writing files safely in section 4 |
