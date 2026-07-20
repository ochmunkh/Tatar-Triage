#!/usr/bin/env bash
#
# TATAR Triage Toolkit (Linux) - tatar-linux.sh
# ---------------------------------------------------------------------------
# Lightweight, single-file DFIR triage / artifact collector for Linux hosts.
# Companion to Tatar.ps1 (Windows). Produces the SAME analyst-first outputs:
#   * summary.txt / summary.json  (unified schema across platforms)
#   * tatar.log                   (timestamped START/OK/WARN/FAILED per module)
#   * manifest_sha256.txt         (SHA-256 of every collected file)
#   * chain_of_custody.txt
#
# Design principles (same as the Windows edition):
#   * Read-only first. No system modification, no package installs.
#   * Order of volatility: network/process -> sessions -> ... -> disk/logs.
#   * Transparent, not evasive. Meant to be reviewed, signed, and allow-listed.
#   * Findings are LEADS FOR REVIEW, not verdicts.
#
# Targets: Debian/Ubuntu and RHEL/CentOS/Fedora (bash 4+, coreutils).
# Run as root for complete collection (some artifacts need privilege).
#
# Exit codes:  0 = success | 1 = fatal / usage error | 2 = completed with errors
#
# Author: Enkhbat.O (Security Analyst) | TATAR Triage Toolkit - Linux v1.1
# ---------------------------------------------------------------------------

# Do NOT 'set -e': a failing collector must never abort the whole run.
set -o pipefail 2>/dev/null || true

VERSION="1.1"
TOOL="TATAR Triage Toolkit (Linux)"

# ---------------------------------------------------------------------------
# Argument parsing  (-flag / --flag, case-insensitive-ish)
# ---------------------------------------------------------------------------
ALL=0; LIST=0; HELP=0; COMPRESS=0; SILENT=0; DUMP_DELETED=0
OUTPUT_BASE="/tmp/forensic"; CASE_ID=""; EXAMINER=""
MODULES=""; UNKNOWN=""

while [ $# -gt 0 ]; do
    raw="$1"
    key="$(printf '%s' "$raw" | sed 's/^--*//' | tr '[:upper:]' '[:lower:]')"
    case "$key" in
        all)         ALL=1 ;;
        list)        LIST=1 ;;
        help|h|\?)   HELP=1 ;;
        compress)    COMPRESS=1 ;;
        silent|quiet|q) SILENT=1 ;;
        dump-deleted|dumpdeleted) DUMP_DELETED=1 ;;
        modules)     shift; MODULES="$(printf '%s' "$1" | tr ',' ' ')" ;;
        output|outputpath|o) shift; OUTPUT_BASE="$1" ;;
        caseid|case) shift; CASE_ID="$1" ;;
        examiner)    shift; EXAMINER="$1" ;;
        *)           UNKNOWN="$UNKNOWN $raw" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Globals / helpers
# ---------------------------------------------------------------------------
ERROR_COUNT=0
OUTDIR=""
REPORT=""
EXECLOG=""
FINDINGS_FILE=""      # tab-separated: severity \t category \t message \t detail
STATS_FILE=""         # key \t value

c_out() {   # console output, suppressed by --silent
    [ "$SILENT" -eq 1 ] && return 0
    printf '%s\n' "$1"
}

now() { date '+%Y-%m-%d %H:%M:%S'; }
now_ms() { date '+%Y-%m-%d %H:%M:%S.%3N' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S'; }
iso() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

execlog() {  # execlog LEVEL MESSAGE
    [ -z "$EXECLOG" ] && return 0
    printf '[%s] [%-6s] %s\n' "$(now_ms)" "$1" "$2" >> "$EXECLOG"
}

report() { printf '%s\n' "$1" >> "$REPORT"; }
section() { printf '\n===== %s =====\n\n' "$1" >> "$REPORT"; }

add_err() {  # add_err MESSAGE
    ERROR_COUNT=$((ERROR_COUNT+1))
    printf '[%s] ERROR: %s\n' "$(now)" "$1" >> "$REPORT"
    execlog "ERROR" "$1"
}

add_stat() { printf '%s\t%s\n' "$1" "$2" >> "$STATS_FILE"; }

# Centralized MITRE ATT&CK mapping - keep all technique logic in ONE place.
map_technique() {  # map_technique CATEGORY MESSAGE -> space-separated technique IDs
    local c="$1" m="$2"
    case "$c" in
        network)     echo "T1565.001" ;;
        process)     case "$m" in *DELETED*) echo "T1620 T1070.004";; *) echo "T1059";; esac ;;
        sessions)    echo "T1110" ;;
        users)       case "$m" in *"UID 0"*) echo "T1136 T1078";; *) echo "T1078";; esac ;;
        persistence) echo "T1053.003" ;;
        suid)        echo "T1548.001" ;;
        sshkeys)     echo "T1098.004" ;;
        bashhistory) echo "T1552.003" ;;
        indicators)  case "$m" in *writable*) echo "T1222.002";; *) echo "T1036";; esac ;;
        context)     echo "T1610" ;;
        *)           echo "" ;;
    esac
}

add_finding() {  # add_finding SEVERITY CATEGORY MESSAGE DETAIL [TECHNIQUE(s)]
    local sev="$1" cat="$2" msg="$3" det="$4" tech="${5:-}"
    msg=$(printf '%s' "$msg" | tr '\t\n' '  ')
    det=$(printf '%s' "$det" | tr '\t\n' '  ')
    [ -z "$tech" ] && tech="$(map_technique "$cat" "$msg")"
    printf '%s\t%s\t%s\t%s\t%s\n' "$sev" "$cat" "$msg" "$det" "$tech" >> "$FINDINGS_FILE"
}

have() { command -v "$1" >/dev/null 2>&1; }

# Execution-context detection (container / virtualization / LSM). Best-effort.
ENV_VIRT="unknown"; ENV_CONTAINER=false; ENV_RUNTIME="none"; ENV_SECMOD="none"
detect_environment() {
    have systemd-detect-virt && ENV_VIRT="$(systemd-detect-virt 2>/dev/null || echo unknown)"
    [ -f /.dockerenv ] && { ENV_CONTAINER=true; ENV_RUNTIME="docker"; }
    if grep -qaE 'kubepods' /proc/1/cgroup 2>/dev/null; then ENV_CONTAINER=true; ENV_RUNTIME="kubernetes"
    elif grep -qaE 'libpod' /proc/1/cgroup 2>/dev/null; then ENV_CONTAINER=true; ENV_RUNTIME="podman"
    elif grep -qaE 'docker|containerd' /proc/1/cgroup 2>/dev/null; then ENV_CONTAINER=true; [ "$ENV_RUNTIME" = none ] && ENV_RUNTIME="docker"
    elif grep -qaE '/lxc/' /proc/1/cgroup 2>/dev/null; then ENV_CONTAINER=true; ENV_RUNTIME="lxc"; fi
    case "$ENV_VIRT" in
        docker) ENV_CONTAINER=true; ENV_RUNTIME="docker" ;;
        podman) ENV_CONTAINER=true; ENV_RUNTIME="podman" ;;
        lxc|lxc-libvirt) ENV_CONTAINER=true; ENV_RUNTIME="lxc" ;;
    esac
    if have getenforce; then ENV_SECMOD="selinux-$(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    elif have aa-status || [ -d /sys/kernel/security/apparmor ]; then ENV_SECMOD="apparmor"; fi
}

# JSON string escaper (arg -> escaped, no surrounding quotes)
json_escape() {
    printf '%s' "$1" | python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read())[1:-1])' 2>/dev/null \
    || printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r' | tr '\n\t' '  '
}

banner() {
    [ "$SILENT" -eq 1 ] && return 0
    cat <<'EOF'

   _____  _    _____  _    ____
  |_   _|/ \  |_   _|/ \  |  _ \
    | | / _ \   | | / _ \ | |_) |
    | |/ ___ \  | |/ ___ \|  _ <
    |_/_/   \_\ |_/_/   \_\_| \_\

+==============================================================+
|   TATAR TRIAGE TOOLKIT  (Linux)   v1.1                       |
|   Fast DFIR triage / artifact collector                      |
|   Transparent - review, sign & allow-list; do not evade      |
+==============================================================+
EOF
}

show_help() {
cat <<EOF
$TOOL v$VERSION

USAGE:
  sudo ./tatar-linux.sh --all                     Run all modules (order of volatility)
  sudo ./tatar-linux.sh --modules network,process Run selected modules
  ./tatar-linux.sh --list                         List available modules
  ./tatar-linux.sh --help                         Show this help

OPTIONS:
  --output <path>   Output base dir (default /tmp/forensic; PREFER external media)
  --caseid <id>     Case / incident id for chain of custody
  --examiner <name> Examiner name for chain of custody
  --compress        tar.gz + SHA-256 the output at the end
  --silent|--quiet  No console output (for SSH/cron/remote runs)
  --dump-deleted    Recover deleted running binaries via /proc/PID/exe (opt-in; off by default)

OUTPUT (always written):
  summary.txt / summary.json   Analyst-first triage summary + aggregated findings
  tatar.log                    Timestamped execution log (START/OK/WARN/FAILED)
  manifest_sha256.txt          SHA-256 of every collected file
  chain_of_custody.txt

EXIT CODES:  0 = success | 1 = fatal / usage error | 2 = completed with errors

NOTES:
  * Run as root for complete collection.
  * Do NOT reboot the host before collection finishes.
  * Findings are review LEADS, not verdicts - validate against the full report.
EOF
}

# ---------------------------------------------------------------------------
# Collector modules  (order of volatility)
# ---------------------------------------------------------------------------

m_sysinfo() {
    section "01 System information"
    { echo "Hostname : $(hostname 2>/dev/null)"
      echo "Date     : $(date)"
      echo "Uptime   : $(uptime 2>/dev/null)"
      echo "Kernel   : $(uname -a)"
      echo "TimeZone : $( (timedatectl 2>/dev/null | grep -i 'time zone') || cat /etc/timezone 2>/dev/null)"
    } >> "$REPORT"
    if [ -r /etc/os-release ]; then echo "--- /etc/os-release ---" >> "$REPORT"; cat /etc/os-release >> "$REPORT" 2>/dev/null; fi
    have lscpu && { echo "--- lscpu ---" >> "$REPORT"; lscpu >> "$REPORT" 2>/dev/null; }
    free -h >> "$REPORT" 2>/dev/null
    df -h  >> "$REPORT" 2>/dev/null
}

m_network() {
    section "02 Network (connections, listening, routes, DNS)"
    if have ss; then
        echo "--- ss -tunap (all sockets, with PID) ---" >> "$REPORT"
        ss -tunap >> "$REPORT" 2>/dev/null
        local lc; lc=$(ss -tlnp 2>/dev/null | grep -c LISTEN)
        add_stat "ListeningTcpPorts" "${lc:-0}"
        local ec; ec=$(ss -tuna 2>/dev/null | grep -c ESTAB)
        add_stat "EstablishedConnections" "${ec:-0}"
    elif have netstat; then
        echo "--- netstat -tunap ---" >> "$REPORT"; netstat -tunap >> "$REPORT" 2>/dev/null
    elif have lsof; then
        echo "--- lsof -i -nP (network connections) ---" >> "$REPORT"; lsof -i -nP >> "$REPORT" 2>/dev/null
    fi
    { echo "--- ip addr ---"; ip addr 2>/dev/null || ifconfig -a 2>/dev/null; } >> "$REPORT"
    { echo "--- ip route ---"; ip route 2>/dev/null || route -n 2>/dev/null; } >> "$REPORT"
    { echo "--- arp / neighbours ---"; ip neigh 2>/dev/null || arp -a 2>/dev/null; } >> "$REPORT"
    for f in /etc/resolv.conf /etc/hosts; do
        [ -r "$f" ] && { echo "--- $f ---" >> "$REPORT"; cat "$f" >> "$REPORT" 2>/dev/null; }
    done
    if [ -r /etc/hosts ]; then
        local hx; hx=$(grep -vE '^\s*#|^\s*$|127\.0\.0\.1|::1|127\.0\.1\.1' /etc/hosts 2>/dev/null | wc -l)
        [ "${hx:-0}" -gt 0 ] && add_finding "Review" "network" "/etc/hosts has $hx custom entries" "Review /etc/hosts in report - static host overrides can redirect traffic (T1565.001)"
    fi
    report "Network artifacts saved."
}

m_process() {
    section "03 Processes (+ suspicious execution locations)"
    ps auxww >> "$REPORT" 2>/dev/null
    local pc; pc=$(ps -e --no-headers 2>/dev/null | wc -l); add_stat "Processes" "${pc:-0}"
    echo "" >> "$REPORT"; echo "-- Process tree --" >> "$REPORT"
    (ps -ejH 2>/dev/null || ps axf 2>/dev/null) >> "$REPORT"
    echo "" >> "$REPORT"; echo "-- /proc exe analysis --" >> "$REPORT"
    local pid exe cmd
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null) || continue
        [ -z "$exe" ] && continue
        cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        case "$exe" in
            *"(deleted)"*)
                echo "[!] PID $pid deleted-binary exe: $exe | cmd: $cmd" >> "$REPORT"
                add_finding "High" "process" "Running process from a DELETED binary (PID $pid)" "$exe | cmd: $cmd"
                if [ "$DUMP_DELETED" -eq 1 ]; then
                    dd_dir="$OUTDIR/extracted_binaries"; mkdir -p "$dd_dir" 2>/dev/null
                    if cp "/proc/$pid/exe" "$dd_dir/pid_${pid}_recovered" 2>/dev/null; then
                        echo "[i] Recovered deleted binary -> extracted_binaries/pid_${pid}_recovered" >> "$REPORT"
                        execlog "INFO" "Recovered deleted binary from PID $pid (--dump-deleted)"
                    fi
                fi
                ;;
            /tmp/*|/dev/shm/*|/var/tmp/*|/run/*)
                echo "[!] PID $pid exe in volatile/world-writable path: $exe | cmd: $cmd" >> "$REPORT"
                add_finding "High" "process" "Process executing from suspicious path (PID $pid)" "$exe | cmd: $cmd" ;;
        esac
    done
    echo "" >> "$REPORT"; echo "-- Suspicious command-line patterns --" >> "$REPORT"
    local pat
    for pat in 'nc -e' 'ncat' '/dev/tcp/' 'bash -i' 'python -c' 'perl -e' 'base64 -d' 'xmrig' 'kinsing' 'kdevtmpfsi'; do
        ps auxww 2>/dev/null | grep -iE "$pat" | grep -v 'grep' >> "$REPORT" 2>/dev/null
    done
}

m_sessions() {
    section "04 Logins & sessions (who, last, failed)"
    { echo "-- who --"; who 2>/dev/null; echo "-- w --"; w 2>/dev/null; } >> "$REPORT"
    { echo "-- last (recent logins) --"; last -n 50 2>/dev/null; } >> "$REPORT"
    echo "-- lastb (failed logins) --" >> "$REPORT"
    local fb; fb=$(lastb -n 200 2>/dev/null)
    printf '%s\n' "$fb" >> "$REPORT"
    local fc; fc=$(printf '%s\n' "$fb" | grep -cE 'tty|pts|ssh')
    add_stat "RecentFailedLogins" "${fc:-0}"
    [ "${fc:-0}" -ge 50 ] && add_finding "Review" "sessions" "High volume of failed logins: ${fc}+ in lastb" "Possible brute force - review source IPs in report section 04"
    local al=""
    [ -r /var/log/auth.log ] && al=/var/log/auth.log
    [ -z "$al" ] && [ -r /var/log/secure ] && al=/var/log/secure
    if [ -n "$al" ]; then
        echo "-- $al (accepted/failed/sudo, last 200) --" >> "$REPORT"
        grep -iE 'accepted|failed password|sudo:|new user|useradd' "$al" 2>/dev/null | tail -n 200 >> "$REPORT"
    elif have journalctl; then
        echo "-- journalctl sshd (last 200) --" >> "$REPORT"
        journalctl _COMM=sshd -n 200 --no-pager 2>/dev/null >> "$REPORT"
    fi
}

m_users() {
    section "05 Users, groups, sudo"
    for f in /etc/passwd /etc/group; do [ -r "$f" ] && { echo "--- $f ---" >> "$REPORT"; cat "$f" >> "$REPORT"; }; done
    echo "--- sudoers ---" >> "$REPORT"
    cat /etc/sudoers 2>/dev/null >> "$REPORT"
    cat /etc/sudoers.d/* 2>/dev/null >> "$REPORT"
    if [ -r /etc/passwd ]; then
        local uc; uc=$(wc -l < /etc/passwd); add_stat "Accounts" "${uc:-0}"
        awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null | while read -r u; do
            [ "$u" != "root" ] && add_finding "High" "users" "Non-root account with UID 0: $u" "Second UID-0 account = full root privileges (backdoor account)"
        done
        echo "--- accounts with login shell ---" >> "$REPORT"
        awk -F: '($7 ~ /(bash|sh|zsh|ksh)$/){print $1" "$7}' /etc/passwd >> "$REPORT" 2>/dev/null
    fi
    if [ -r /etc/shadow ]; then
        awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | while read -r u; do
            add_finding "High" "users" "Account with EMPTY password: $u" "Login with no password possible - see /etc/shadow"
        done
    else
        report "(/etc/shadow not readable - run as root for empty-password check)"
    fi
}

m_services() {
    section "06 Services / units"
    if have systemctl; then
        echo "-- running services --" >> "$REPORT"
        systemctl list-units --type=service --state=running --no-pager --no-legend >> "$REPORT" 2>/dev/null
        echo "-- enabled unit files --" >> "$REPORT"
        systemctl list-unit-files --state=enabled --no-pager --no-legend >> "$REPORT" 2>/dev/null
        local sc; sc=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | wc -l)
        add_stat "RunningServices" "${sc:-0}"
    elif have service; then
        service --status-all >> "$REPORT" 2>/dev/null
    else
        ls -la /etc/init.d 2>/dev/null >> "$REPORT"
    fi
}

m_persistence() {
    section "07 Persistence (cron, systemd timers, rc, profiles)"
    echo "-- system crontab & cron dirs --" >> "$REPORT"
    for f in /etc/crontab /etc/cron.d/* ; do [ -r "$f" ] && { echo "[$f]" >> "$REPORT"; cat "$f" >> "$REPORT"; }; done
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$d" ] && { echo "[$d]" >> "$REPORT"; ls -la "$d" >> "$REPORT" 2>/dev/null; }
    done
    echo "-- per-user crontabs --" >> "$REPORT"
    for cdir in /var/spool/cron /var/spool/cron/crontabs; do
        [ -d "$cdir" ] && find "$cdir" -type f 2>/dev/null | while read -r cf; do echo "[$cf]" >> "$REPORT"; cat "$cf" >> "$REPORT" 2>/dev/null; done
    done
    grep -rhiE 'curl|wget|/dev/tcp/|base64|nc |ncat|python -c|bash -i' /etc/crontab /etc/cron.d /var/spool/cron 2>/dev/null | while read -r line; do
        add_finding "Review" "persistence" "Suspicious cron command" "$line"
    done
    echo "-- systemd timers --" >> "$REPORT"
    have systemctl && systemctl list-timers --all --no-pager --no-legend >> "$REPORT" 2>/dev/null
    echo "-- rc.local / init --" >> "$REPORT"
    for f in /etc/rc.local /etc/rc.d/rc.local; do [ -r "$f" ] && { echo "[$f]" >> "$REPORT"; cat "$f" >> "$REPORT"; }; done
    echo "-- shell profile scripts --" >> "$REPORT"
    for f in /etc/profile /etc/bash.bashrc /etc/profile.d/*; do [ -r "$f" ] && echo "[$f] ($(stat -c '%y' "$f" 2>/dev/null))" >> "$REPORT"; done
}

m_apps() {
    section "08 Installed packages"
    if have dpkg; then dpkg -l >> "$REPORT" 2>/dev/null
    elif have rpm; then rpm -qa >> "$REPORT" 2>/dev/null
    else report "No dpkg/rpm found."; fi
}

m_suid() {
    section "09 SUID / SGID binaries"
    echo "-- SUID --" >> "$REPORT"
    local list; list=$(find / -xdev -perm -4000 -type f 2>/dev/null)
    printf '%s\n' "$list" >> "$REPORT"
    echo "-- SGID --" >> "$REPORT"
    find / -xdev -perm -2000 -type f 2>/dev/null >> "$REPORT"
    printf '%s\n' "$list" | grep -vE '^/(usr/bin|bin|usr/sbin|sbin|usr/lib|lib|usr/libexec)/' | grep -E '.' | while read -r s; do
        [ -n "$s" ] && add_finding "Review" "suid" "SUID binary outside standard paths: $s" "Unusual SUID location can indicate privilege-escalation backdoor (T1548.001)"
    done
}

m_sshkeys() {
    section "10 SSH keys & config"
    echo "-- sshd_config (key settings) --" >> "$REPORT"
    grep -iE 'permitrootlogin|passwordauthentication|authorizedkeysfile|^port |permitemptypasswords' /etc/ssh/sshd_config 2>/dev/null >> "$REPORT"
    echo "-- authorized_keys across homes --" >> "$REPORT"
    local ak
    for h in /root /home/*; do
        ak="$h/.ssh/authorized_keys"
        if [ -r "$ak" ]; then
            echo "[$ak] ($(wc -l < "$ak" 2>/dev/null) keys, modified $(stat -c '%y' "$ak" 2>/dev/null))" >> "$REPORT"
            cat "$ak" >> "$REPORT" 2>/dev/null
            [ "$h" = "/root" ] && add_finding "Review" "sshkeys" "root has authorized_keys ($(wc -l < "$ak" 2>/dev/null) entries)" "Verify these keys are expected - unexpected key = remote backdoor (T1098.004)"
        fi
    done
}

m_bashhistory() {
    section "11 Shell history"
    local hf
    for h in /root /home/*; do
        for hf in "$h/.bash_history" "$h/.zsh_history" "$h/.ash_history"; do
            if [ -r "$hf" ]; then
                echo "[$hf]" >> "$REPORT"; cat "$hf" >> "$REPORT" 2>/dev/null; echo "" >> "$REPORT"
                grep -hiE 'wget|curl|nc |ncat|/dev/tcp/|base64|chmod \+x|chattr|history -c|useradd|passwd ' "$hf" 2>/dev/null | while read -r line; do
                    add_finding "Review" "bashhistory" "Notable history command in ${hf##*/}" "$line"
                done
            fi
        done
    done
}

m_kernelmods() {
    section "12 Kernel modules"
    have lsmod && lsmod >> "$REPORT" 2>/dev/null
    echo "-- tainted state --" >> "$REPORT"
    cat /proc/sys/kernel/tainted 2>/dev/null >> "$REPORT"
}

m_indicators() {
    section "13 Suspicious indicators"
    echo "-- world-writable files in system dirs --" >> "$REPORT"
    find /etc /bin /sbin /usr/bin /usr/sbin -xdev -type f -perm -0002 2>/dev/null | while read -r f; do
        echo "[!] world-writable: $f" >> "$REPORT"
        add_finding "Review" "indicators" "World-writable system file: $f" "System binaries/config should not be world-writable"
    done
    echo "-- executables in /tmp /dev/shm /var/tmp --" >> "$REPORT"
    local tc=0 d
    for d in /tmp /dev/shm /var/tmp; do
        [ -d "$d" ] || continue
        find "$d" -xdev -type f -perm -111 ! -path "$OUTPUT_BASE/*" ! -path "$OUTDIR/*" 2>/dev/null >> "$REPORT"
        tc=$((tc + $(find "$d" -xdev -type f -perm -111 ! -path "$OUTPUT_BASE/*" ! -path "$OUTDIR/*" 2>/dev/null | wc -l)))
    done
    add_stat "ExecInTempDirs" "${tc:-0}"
    [ "${tc:-0}" -gt 0 ] && add_finding "Review" "indicators" "${tc} executable file(s) in /tmp,/dev/shm,/var/tmp" "See report section 13 - legitimate installers also appear; validate"
    echo "-- recently modified files in /etc (7 days) --" >> "$REPORT"
    find /etc -xdev -type f -mtime -7 2>/dev/null | head -n 200 >> "$REPORT"
    echo "-- immutable files (chattr +i) in /etc /root --" >> "$REPORT"
    have lsattr && lsattr -R /etc /root 2>/dev/null | grep -E '^....i' >> "$REPORT"
}

m_hashes() {
    section "14 Hash collection (running binaries)"
    local outf="$OUTDIR/binary_hashes.txt"
    : > "$outf"
    local pid exe seen="|"
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null) || continue
        case "$exe" in ""|*"(deleted)"*) continue;; esac
        case "$seen" in *"|$exe|"*) continue;; esac
        seen="$seen$exe|"
        [ -r "$exe" ] && sha256sum "$exe" 2>/dev/null >> "$outf"
    done
    local hc; hc=$(wc -l < "$outf" 2>/dev/null); add_stat "HashedBinaries" "${hc:-0}"
    report "Hashed ${hc:-0} running binaries -> binary_hashes.txt (feed to VirusTotal / IOC matching)."
}

m_logs() {
    section "15 Key log copy"
    local ld="$OUTDIR/logs"; mkdir -p "$ld" 2>/dev/null
    for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/wtmp /var/log/btmp /var/log/cron; do
        [ -r "$f" ] && cp -p "$f" "$ld/" 2>/dev/null
    done
    report "Copied available key logs to logs/."
}

m_timeline() {
    section "16 Timeline (recent file changes, super-timeline lite)"
    local tf="$OUTDIR/timeline.csv"
    echo "MTime,Path,Source" > "$tf"
    find /etc /root /home /usr/local/bin /tmp /var/tmp /dev/shm -xdev -type f -mtime -14 ! -path "$OUTPUT_BASE/*" 2>/dev/null | head -n 5000 | while read -r f; do
        printf '"%s","%s","fs"\n' "$(stat -c '%y' "$f" 2>/dev/null)" "$f" >> "$tf"
    done
    local n; n=$(( $(wc -l < "$tf" 2>/dev/null) - 1 )); [ "$n" -lt 0 ] && n=0
    add_stat "TimelineEntries" "$n"
    report "Timeline entries: $n -> timeline.csv"
}

m_containers() {
    section "17 Containers & cloud context"
    if [ "$ENV_CONTAINER" = "true" ]; then
        add_finding "Review" "context" "TATAR is running INSIDE a container ($ENV_RUNTIME)" "Collected artifacts reflect the container, not necessarily the host - correlate with host-level triage (T1610)"
    fi
    if have docker; then
        echo "-- docker ps -a --" >> "$REPORT"; docker ps -a --no-trunc >> "$REPORT" 2>/dev/null
        echo "-- docker images --" >> "$REPORT"; docker images >> "$REPORT" 2>/dev/null
        echo "-- docker networks --" >> "$REPORT"; docker network ls >> "$REPORT" 2>/dev/null
        local dc; dc=$(docker ps -q 2>/dev/null | wc -l); add_stat "RunningContainers" "${dc:-0}"
    else
        report "Docker CLI not present / daemon not reachable."
    fi
    if have podman; then echo "-- podman ps -a --" >> "$REPORT"; podman ps -a >> "$REPORT" 2>/dev/null; fi
}

m_integrity() {
    section "18 Critical file integrity (SHA-256 baseline)"
    local f h
    for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/crontab /etc/ssh/sshd_config; do
        if [ -r "$f" ]; then
            h=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
            printf '%s  %s\n' "$h" "$f" >> "$REPORT"
        fi
    done
    report "Critical-file hashes recorded (compare across runs to detect tampering)."
}

# ---------------------------------------------------------------------------
# Module registry (order of volatility)
# ---------------------------------------------------------------------------
MOD_NAMES="sysinfo network process sessions users services persistence apps suid sshkeys bashhistory kernelmods indicators hashes logs timeline containers integrity"

run_module() {
    case "$1" in
        sysinfo) m_sysinfo ;;
        network) m_network ;;
        process) m_process ;;
        sessions) m_sessions ;;
        users) m_users ;;
        services) m_services ;;
        persistence) m_persistence ;;
        apps) m_apps ;;
        suid) m_suid ;;
        sshkeys) m_sshkeys ;;
        bashhistory) m_bashhistory ;;
        kernelmods) m_kernelmods ;;
        indicators) m_indicators ;;
        hashes) m_hashes ;;
        logs) m_logs ;;
        timeline) m_timeline ;;
        containers) m_containers ;;
        integrity) m_integrity ;;
        *) return 99 ;;
    esac
}

# ---------------------------------------------------------------------------
# Summary writer (unified schema with the Windows edition)
# ---------------------------------------------------------------------------
write_summary() {
    local start_iso="$1" end_iso="$2" mods="$3" is_root="$4" dur="$5"
    local hn os osv usr fcount TAB
    TAB="$(printf '\t')"
    hn="$(hostname 2>/dev/null)"
    os="$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-$(uname -s)}" )"
    osv="$(uname -r)"
    usr="$(id -un 2>/dev/null)"
    fcount=$( [ -s "$FINDINGS_FILE" ] && wc -l < "$FINDINGS_FILE" || echo 0 )

    local S="$OUTDIR/summary.txt"
    {
        echo "=============================================================="
        echo " $TOOL v$VERSION - TRIAGE SUMMARY"
        echo "=============================================================="
        echo "Host       : $hn"
        echo "OS         : $os ($osv)"
        echo "User       : $usr"
        echo "Case ID    : $CASE_ID"
        echo "Examiner   : $EXAMINER"
        echo "Started    : $start_iso"
        echo "Finished   : $end_iso"
        echo "Duration   : ${dur}s"
        echo "Privileged : $is_root"
        echo "Environment: virt=$ENV_VIRT container=$ENV_CONTAINER runtime=$ENV_RUNTIME secmod=$ENV_SECMOD"
        echo "Modules    : $mods"
        echo "Errors     : $ERROR_COUNT (see tatar.log)"
        echo ""
        echo "-------------------- QUICK STATS ----------------------------"
        if [ -s "$STATS_FILE" ]; then
            while IFS="$TAB" read -r k v; do printf '  %-24s : %s\n' "$k" "$v"; done < "$STATS_FILE"
        else
            echo "  (no stats collected)"
        fi
        echo ""
        echo "---------- SUSPICIOUS FINDINGS: $fcount (review leads, NOT verdicts) ----------"
        if [ -s "$FINDINGS_FILE" ]; then
            for sev in High Review; do
                while IFS="$TAB" read -r fs fc fm fd ft; do
                    [ "$fs" = "$sev" ] || continue
                    if [ -n "$ft" ]; then printf '  [%s] (%s) [%s] %s\n' "$fs" "$fc" "$ft" "$fm"
                    else printf '  [%s] (%s) %s\n' "$fs" "$fc" "$fm"; fi
                    [ -n "$fd" ] && printf '        %s\n' "$fd"
                done < "$FINDINGS_FILE"
            done
            echo ""
            echo "  NOTE: entries above are automated pattern matches. Legitimate software"
            echo "  and admin activity can appear. Validate each lead against the full"
            echo "  report before drawing conclusions."
        else
            echo "  No automatic findings were flagged. This does NOT prove the host is"
            echo "  clean - review the full report and collected artifacts."
        fi
        echo ""
        echo "-------------------- NEXT STEPS ------------------------------"
        echo "  1. Review findings against the full report .txt"
        echo "  2. Check tatar.log for FAILED/WARN steps (missing evidence)."
        echo "  3. Submit binary_hashes.txt to VirusTotal / IOC matching."
        echo "  4. Pivot on timeline.csv around confirmed finding timestamps."
    } > "$S"

    local J="$OUTDIR/summary.json"
    {
        printf '{\n'
        printf '  "tool": "%s",\n' "$(json_escape "$TOOL")"
        printf '  "version": "%s",\n' "$VERSION"
        printf '  "schemaVersion": "1.1",\n'
        printf '  "platform": "linux",\n'
        printf '  "host": "%s",\n' "$(json_escape "$hn")"
        printf '  "os": "%s",\n' "$(json_escape "$os")"
        printf '  "osVersion": "%s",\n' "$(json_escape "$osv")"
        printf '  "user": "%s",\n' "$(json_escape "$usr")"
        printf '  "caseId": "%s",\n' "$(json_escape "$CASE_ID")"
        printf '  "examiner": "%s",\n' "$(json_escape "$EXAMINER")"
        printf '  "started": "%s",\n' "$start_iso"
        printf '  "finished": "%s",\n' "$end_iso"
        printf '  "durationSeconds": %s,\n' "${dur:-0}"
        printf '  "privileged": %s,\n' "$is_root"
        printf '  "environment": {"virtualization":"%s","container":%s,"containerRuntime":"%s","securityModule":"%s"},\n' "$(json_escape "$ENV_VIRT")" "$ENV_CONTAINER" "$(json_escape "$ENV_RUNTIME")" "$(json_escape "$ENV_SECMOD")"
        printf '  "errorsLogged": %s,\n' "$ERROR_COUNT"
        printf '  "modulesRun": ['
        local first=1 m
        for m in $mods; do [ $first -eq 1 ] && first=0 || printf ', '; printf '"%s"' "$m"; done
        printf '],\n'
        printf '  "stats": {'
        if [ -s "$STATS_FILE" ]; then
            first=1
            while IFS="$TAB" read -r k v; do
                [ $first -eq 1 ] && first=0 || printf ','
                printf '"%s": "%s"' "$(json_escape "$k")" "$(json_escape "$v")"
            done < "$STATS_FILE"
        fi
        printf '},\n'
        printf '  "findingsCount": %s,\n' "$fcount"
        printf '  "findings": ['
        if [ -s "$FINDINGS_FILE" ]; then
            first=1
            while IFS="$TAB" read -r fs fc fm fd ft; do
                [ $first -eq 1 ] && first=0 || printf ','
                if [ -n "$ft" ]; then techjson=$(printf '%s' "$ft" | awk '{printf "[";for(i=1;i<=NF;i++)printf "%s\"%s\"",(i>1?",":""),$i;printf "]"}'); else techjson="[]"; fi
                printf '{"severity":"%s","category":"%s","technique":%s,"message":"%s","detail":"%s"}' \
                    "$(json_escape "$fs")" "$(json_escape "$fc")" "$techjson" "$(json_escape "$fm")" "$(json_escape "$fd")"
            done < "$FINDINGS_FILE"
        fi
        printf ']\n'
        printf '}\n'
    } > "$J"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
banner
for u in $UNKNOWN; do c_out "[!] Unknown option: $u"; done

if [ "$HELP" -eq 1 ]; then show_help; exit 0; fi
if [ "$LIST" -eq 1 ]; then
    echo "Available modules (order of volatility):"; echo ""
    for m in $MOD_NAMES; do echo "  $m"; done
    echo ""; echo "Total: $(echo $MOD_NAMES | wc -w) modules"; exit 0
fi

TO_RUN=""
if [ "$ALL" -eq 1 ]; then TO_RUN="$MOD_NAMES"
elif [ -n "$MODULES" ]; then TO_RUN="$MODULES"
else
    [ "$SILENT" -eq 0 ] && { show_help; echo ""; echo "[i] Nothing selected. Use --all or --modules."; }
    exit 1
fi

IS_ROOT=false; [ "$(id -u)" -eq 0 ] && IS_ROOT=true
[ "$IS_ROOT" = false ] && c_out "[!] Not running as root - some artifacts will be incomplete."

HOSTN="$(hostname 2>/dev/null | tr ' /' '__')"
STAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
OUTDIR="$OUTPUT_BASE/${HOSTN}_${STAMP}"
if ! mkdir -p "$OUTDIR" 2>/dev/null; then
    [ "$SILENT" -eq 0 ] && echo "[x] FATAL: cannot create output dir $OUTDIR"
    exit 1
fi
REPORT="$OUTDIR/TATAR_Report_${HOSTN}_${STAMP}.txt"
EXECLOG="$OUTDIR/tatar.log"
FINDINGS_FILE="$(mktemp)"; STATS_FILE="$(mktemp)"

execlog "INFO" "$TOOL v$VERSION starting on $HOSTN as $(id -un) (root=$IS_ROOT, silent=$SILENT)"
execlog "INFO" "CaseId='$CASE_ID' Examiner='$EXAMINER' OutDir=$OUTDIR"
execlog "INFO" "Modules selected: $TO_RUN"
[ "$IS_ROOT" = false ] && execlog "WARN" "Not running as root - collection will be incomplete."

{
    echo "$TOOL v$VERSION - Collection Report"
    echo "Host        : $HOSTN"
    echo "Case ID     : $CASE_ID"
    echo "Examiner    : $EXAMINER"
    echo "Started     : $(iso)"
    echo "Root        : $IS_ROOT"
    echo "Modules     : $TO_RUN"
    echo "OutputDir   : $OUTDIR"
} > "$REPORT"

START_ISO="$(iso)"; START_EPOCH="$(date +%s)"
detect_environment
execlog "INFO" "Environment: virt=$ENV_VIRT container=$ENV_CONTAINER runtime=$ENV_RUNTIME secmod=$ENV_SECMOD"
c_out ""; c_out "[i] Output: $OUTDIR"
c_out "[i] Env: virt=$ENV_VIRT container=$ENV_CONTAINER runtime=$ENV_RUNTIME secmod=$ENV_SECMOD"
c_out ""

I=0; N=$(echo $TO_RUN | wc -w); RAN=0
for m in $TO_RUN; do
    I=$((I+1))
    if ! echo " $MOD_NAMES " | grep -q " $m "; then
        c_out "[!] Unknown module: $m"; execlog "WARN" "Unknown module requested: $m"; continue
    fi
    c_out "[$I/$N] $m"
    execlog "START" "module $m ($I/$N)"
    err_before=$ERROR_COUNT; mstart=$(date +%s)
    run_module "$m"; RAN=$((RAN+1))
    secs=$(( $(date +%s) - mstart ))
    if [ "$ERROR_COUNT" -gt "$err_before" ]; then
        execlog "WARN" "module $m finished in ${secs}s with $((ERROR_COUNT-err_before)) error(s)"
    else
        execlog "OK" "module $m finished in ${secs}s"
    fi
done

if [ "$RAN" -eq 0 ]; then c_out "[x] No valid modules were run."; execlog "FATAL" "No valid modules were run."; exit 1; fi

c_out ""; c_out "[i] Finalizing (summary, metadata, manifest)..."
END_ISO="$(iso)"; DUR=$(( $(date +%s) - START_EPOCH ))

SELF="$0"; SELF_HASH="$(sha256sum "$SELF" 2>/dev/null | awk '{print $1}')"
{
    echo "=== CHAIN OF CUSTODY ==="
    echo "Case ID      : $CASE_ID"
    echo "Examiner     : $EXAMINER"
    echo "Host         : $HOSTN"
    echo "Started      : $START_ISO"
    echo "Finished     : $END_ISO"
    echo "Duration     : ${DUR}s"
    echo "Script       : $SELF"
    echo "Script SHA256: $SELF_HASH"
    echo "Tool         : $TOOL v$VERSION"
} > "$OUTDIR/chain_of_custody.txt"

execlog "INFO" "Writing summary.txt / summary.json"
write_summary "$START_ISO" "$END_ISO" "$TO_RUN" "$IS_ROOT" "$DUR"

MANIFEST="$OUTDIR/manifest_sha256.txt"
( cd "$OUTDIR" && find . -type f ! -name 'manifest_sha256.txt' ! -name 'tatar.log' -exec sha256sum {} \; ) > "$MANIFEST" 2>/dev/null
execlog "INFO" "Manifest written: $MANIFEST"

printf '\n=== Collection finished: %s ===\n' "$END_ISO" >> "$REPORT"

if [ "$COMPRESS" -eq 1 ]; then
    ARCHIVE="$OUTPUT_BASE/TATAR_${HOSTN}_${STAMP}.tar.gz"
    if tar -czf "$ARCHIVE" -C "$OUTPUT_BASE" "${HOSTN}_${STAMP}" 2>/dev/null; then
        sha256sum "$ARCHIVE" 2>/dev/null | awk '{print $1}' > "${ARCHIVE}.sha256.txt"
        execlog "INFO" "Archive created + hashed: $ARCHIVE"
        c_out "[i] Archive: $ARCHIVE"
    else
        add_err "Compression failed"; c_out "[!] Compression failed"
    fi
fi

EXIT_CODE=0; [ "$ERROR_COUNT" -gt 0 ] && EXIT_CODE=2
FCOUNT=$( [ -s "$FINDINGS_FILE" ] && wc -l < "$FINDINGS_FILE" || echo 0 )
execlog "INFO" "Run complete. Findings: $FCOUNT | Errors: $ERROR_COUNT | Exit code: $EXIT_CODE"

rm -f "$FINDINGS_FILE" "$STATS_FILE" 2>/dev/null

c_out ""
c_out "[+] Done. Report  : $REPORT"
c_out "[+] Summary : $OUTDIR/summary.txt"
c_out "[+] Findings: $FCOUNT lead(s) for review | Errors logged: $ERROR_COUNT | Exit code: $EXIT_CODE"
c_out "[i] Findings are review leads, not verdicts. Encrypt & handle output per policy."
exit $EXIT_CODE
