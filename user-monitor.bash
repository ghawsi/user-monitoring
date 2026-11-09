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
