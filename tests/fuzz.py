#!/usr/bin/env python3
"""TATAR Triage Toolkit - fuzz tests (Linux edition).

The security tests ask whether the collector survives hostile input somebody
thought of. This asks the same question of input nobody thought of: random and
mutated bytes go to the places where text from the suspect host or from a feed
file is parsed, and a property that must hold for EVERY input is checked.

  F1  json_escape     the output, wrapped in quotes, parses and decodes back to
                      the exact input (the SIEM contract rests on this one
                      function)
  F2  csv_cell        no field can begin a spreadsheet formula, and a double
                      quote is always doubled
  F3  hosts_entry     only legal address / name characters survive, never a
                      slash, backslash, quote or control character
  F4  al_paths_of     every extracted token is an absolute path made of the
                      allowed characters, nothing else
  F5  san_into        no control, escape or bidi character survives
  F6  feeds           a mutated allowlist or IOC file never crashes or hangs a
                      run: exit 0 or 2, summary.json still valid, no shell
                      error text on stderr

A fixed seed makes a run reproducible; set TATAR_FUZZ_SEED to vary it. The seed
and the failing input are printed on any failure.

    python3 tests/fuzz.py [collector] [--iterations N] [--feed-iterations N]

Exit code: 0 = no property violated, 1 = at least one.
"""
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
args = [a for i, a in enumerate(sys.argv[1:], 1)
        if not a.startswith("--") and not sys.argv[i - 1].startswith("--")]
COLLECTOR = args[0] if args else os.path.join(HERE, "..", "linux", "tatar-linux.sh")


def opt(name, default):
    if name in sys.argv:
        return int(sys.argv[sys.argv.index(name) + 1])
    return default


ITER = opt("--iterations", 1500)
FEED_ITER = opt("--feed-iterations", 60)
SEED = int(os.environ.get("TATAR_FUZZ_SEED", "20261118"))
rng = random.Random(SEED)

passed = failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("  PASS  " + name)
    else:
        failed += 1
        print("  FAIL  %s  %s" % (name, detail))


def lift(fn):
    """The function body, from its definition to the first column-0 brace."""
    out, grab = [], False
    for line in open(COLLECTOR, encoding="utf-8"):
        if not grab and line.startswith(fn + "() {"):
            grab = True
        if grab:
            out.append(line)
            if line.startswith("}"):
                break
    if not out:
        sys.exit("FAIL  %s not found in %s" % (fn, COLLECTOR))
    return "".join(out)


# ---------------------------------------------------------------- generators
INTERESTING = [
    "", " ", "=", "+", "-", "@", "'", '"', "\\", "/", "..", "\t", "\r", "\n",
    "\x1b[31m", "\x1b]0;x\x07", "\x07", "\x7f", "\u202e", "\u2066", "\ufffd", "\u0085",
    "\u2028", "\u2029", "\ufeff", "$(id)", "`id`", ";id", "|id", "&&id", "%s", "%n",
    "*", "?", "[", "]", "{", "}", "~", "\U0001f600", "\u0416", "\u65e5\u672c",
    "/etc/passwd", "C:\\Windows\\System32", "127.0.0.1", "::1", "0" * 40,
]


def rand_text(maxlen=60):
    """Mostly printable, with injected awkward fragments and stray bytes."""
    parts = []
    for _ in range(rng.randint(0, 8)):
        r = rng.random()
        if r < 0.35:
            parts.append(rng.choice(INTERESTING))
        elif r < 0.7:
            parts.append("".join(chr(rng.randint(32, 126)) for _ in range(rng.randint(0, maxlen))))
        elif r < 0.9:
            parts.append("".join(chr(rng.randint(1, 0x2fff)) for _ in range(rng.randint(0, 12))))
        else:
            parts.append("x" * rng.randint(100, 3000))
    s = "".join(parts)
    return s.replace("\x00", "")      # bash strings cannot hold NUL


def mutate(data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        op = rng.randint(0, 6)
        if not b:
            b = bytearray(b"{}")
        i = rng.randrange(len(b))
        if op == 0:
            b[i] = rng.randrange(256)
        elif op == 1:
            del b[i:i + rng.randint(1, 20)]
        elif op == 2:
            b[i:i] = rng.choice(INTERESTING).encode("utf-8", "replace")
        elif op == 3:
            b = b[:i]
        elif op == 4:
            b[i:i] = bytes(b[max(0, i - 30):i]) * rng.randint(2, 50)
        elif op == 5:
            b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 40)))
        else:
            b[i:i] = (b"[" * rng.randint(1, 3000))
    return bytes(b)


# -------------------------------------------------------- bash batch runner
def bash_batch(fn_names, body, inputs, timeout=170):
    """Run `body` once per input inside ONE bash process (fast). Inputs are
    passed NUL-separated on stdin; each result is NUL-terminated on stdout."""
    prelude = "\n".join(lift(f) for f in fn_names)
    script = prelude + "\n" + body
    data = b"".join(s.encode("utf-8", "surrogatepass") + b"\x00" for s in inputs)
    p = subprocess.run(["bash", "-c", script], input=data, capture_output=True, timeout=timeout)
    out = p.stdout.split(b"\x00")
    if out and out[-1] == b"":
        out.pop()
    return out, p.stderr.decode("utf-8", "replace")


READ_LOOP = 'while IFS= read -r -d "" in; do %s; printf "\\0"; done'


def run_property(label, fns, expr, prop, extra_pre=""):
    inputs = [rand_text() for _ in range(ITER)]
    out, err = bash_batch(fns, extra_pre + READ_LOOP % expr, inputs)
    bad = []
    if len(out) != len(inputs):
        check(label + ": every input produced a result", False,
              "%d results for %d inputs; stderr: %s" % (len(out), len(inputs), err[:200]))
        return
    for inp, raw in zip(inputs, out):
        try:
            res = raw.decode("utf-8")
        except UnicodeDecodeError:
            bad.append((inp, raw))
            continue
        if not prop(inp, res):
            bad.append((inp, res))
    check("%s: %d random inputs, property holds (seed %d)" % (label, ITER, SEED), not bad,
          "first violation: input=%r output=%r" % bad[0] if bad else "")


# ------------------------------------------------------------------ targets
print("\nF1  json_escape round-trips every input")
def p_json(inp, res):
    try:
        return json.loads('"%s"' % res) == inp
    except Exception:
        return False
run_property("F1 json_escape", ["json_escape"], 'json_escape "$in"', p_json)

print("\nF2  csv_cell never starts a formula and doubles quotes")
def p_csv(inp, res):
    if re.match(r"^(\t|[=+@])", res):
        return False
    if res.startswith("-") and not re.match(r"^-[0-9][0-9.,\-]*$", res):
        return False
    # the doubling: removing every doubled quote must leave no single quote
    return '"' not in res.replace('""', "")
run_property("F2 csv_cell", ["csv_cell"], 'printf "%s" "$(csv_cell "$in")"', p_csv)

print("\nF3  hosts_entry keeps only legal characters")
def p_hosts(inp, res):
    if re.search(r"[\\/\"'`$;|&<>\x00-\x08\x0b-\x1f\x7f]", res.replace("->", "", 1)):
        return False
    return len(res) <= 103 and "\n" not in res
run_property("F3 hosts_entry", ["hosts_entry"], 'printf "%s" "$(hosts_entry "$in")"', p_hosts)

print("\nF4  al_paths_of emits only absolute paths of allowed characters")
def p_paths(inp, res):
    for tok in [t for t in res.split("\n") if t != ""]:
        if not re.fullmatch(r"/[A-Za-z0-9_.+\-][A-Za-z0-9_./+\-]*", tok):
            return False
    return True
run_property("F4 al_paths_of", ["al_paths_of"], 'al_paths_of "$in" "$in"', p_paths)

print("\nF5  san_into removes control, escape and bidi characters")
def p_san(inp, res):
    return not re.search("[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]", res)
run_property("F5 san_into", ["san_into"], 'san_into o "$in"; printf "%s" "$o"', p_san)

# ------------------------------------------------------------------- feeds
print("\nF6  mutated allowlist and IOC feeds never crash or hang a run")
base = {
    "allowlist": open(os.path.join(HERE, "..", "allowlist.sample.json"), "rb").read(),
    "ioc": open(os.path.join(HERE, "..", "ioc.sample.json"), "rb").read(),
}
SHELL_ERR = re.compile(r"syntax error|unbound variable|command not found|bad substitution|"
                       r"Segmentation|Traceback|core dumped|integer expression expected", re.I)
work = tempfile.mkdtemp(prefix="tatar-fuzz.")
bad_run = []
slowest = 0.0
for n in range(FEED_ITER):
    kind = "allowlist" if n % 2 == 0 else "ioc"
    feed = os.path.join(work, "feed%d.json" % n)
    open(feed, "wb").write(mutate(base[kind]))
    out = os.path.join(work, "out%d" % n)
    flag = "--allowlist" if kind == "allowlist" else "--ioc"
    t0 = time.time()
    try:
        p = subprocess.run(["bash", COLLECTOR, "--modules", "sysinfo", "--silent",
                            "--output", out, flag, feed],
                           capture_output=True, timeout=60)
        code, err = p.returncode, p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        code, err = -1, "TIMEOUT"
    slowest = max(slowest, time.time() - t0)
    why = None
    if code not in (0, 2):
        why = "exit %s" % code
    elif SHELL_ERR.search(err):
        why = "stderr: " + err[:150]
    else:
        dirs = [d for d in os.listdir(out)] if os.path.isdir(out) else []
        if not dirs:
            why = "no evidence folder"
        else:
            try:
                json.load(open(os.path.join(out, dirs[0], "summary.json"), encoding="utf-8"))
            except Exception as e:
                why = "summary.json invalid: %s" % e
    if why:
        keep = os.path.join(tempfile.gettempdir(), "tatar-fuzz-fail-%d.json" % n)
        open(keep, "wb").write(open(feed, "rb").read())
        bad_run.append("%s (%s feed kept at %s)" % (why, kind, keep))
check("F6 feeds: %d mutated feeds, exit 0/2, summary.json valid, no shell errors (slowest %.1fs)"
      % (FEED_ITER, slowest), not bad_run, "; ".join(bad_run[:2]))
check("F6 feeds: no run needed more than 30 s", slowest <= 30, "%.1fs" % slowest)

print("\nRESULT  passed: %d  failed: %d  (seed %d)" % (passed, failed, SEED))
sys.exit(1 if failed else 0)
