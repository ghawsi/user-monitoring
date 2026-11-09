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
