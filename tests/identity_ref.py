#!/usr/bin/env python3
"""Reference implementation of the finding identity canon (schema 1.7) and the
checker for tests/fixtures/identity-vectors.tsv. The Windows and Linux editions
are tested against the same vectors (Test-Identity.ps1, test-identity.sh).

    python3 tests/identity_ref.py            check the vectors
    python3 tests/identity_ref.py --print    print vectors with computed hashes
"""
import hashlib, re, sys, os

US, RS = "\x1f", "\x1e"

def h16(t):
    return hashlib.sha256(t.encode("utf-8")).hexdigest()[:16]

def mask(m):
    m = re.sub(r"\b[Pp][Ii][Dd][ =:]*[0-9]+", "PID N", m)
    return re.sub(r"\b[0-9]+( (?:files?|entries|items|connections?|processes|accounts?|users?|rules?|tasks?|services?|hits?|matches|events?)\b)", r"N\1", m)

def identity(module, cls, cat, msg, detail, sev, conf, paths):
    pl = sorted(p for p in paths if p)
    fp = h16(US.join([module, cls, cat, mask(msg), RS.join(pl)]))
    ch = h16(US.join([sev, conf, detail]))
    return fp, ch

def rows(path):
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        f = line.split("\t")
        out.append(f)
    return out

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    tsv = os.path.join(here, "fixtures", "identity-vectors.tsv")
    bad = 0
    for f in rows(tsv):
        mod, cls, cat, msg, det, sev, conf, paths = f[:8]
        fp, ch = identity(mod, cls, cat, msg, det, sev, conf, paths.split(";;") if paths else [])
        if "--print" in sys.argv:
            print("\t".join(f[:8] + [fp, ch]))
        elif len(f) < 10 or f[8] != fp or f[9] != ch:
            bad += 1
            print("FAIL", msg[:50], fp, ch)
    if "--print" not in sys.argv:
        print("identity vectors: %s" % ("OK" if not bad else "%d failed" % bad))
    sys.exit(1 if bad else 0)
