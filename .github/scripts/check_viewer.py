#!/usr/bin/env python3
"""Gate for tools/viewer.html - the static findings viewer.

The viewer is the one file in this project that renders text taken from an
evidence folder, so the properties that make that safe are checked here
rather than trusted:

  * the Content-Security-Policy hashes match the script and the style that are
    actually in the file (a viewer whose policy no longer matches its script
    either breaks or, worse, was loosened to make it work);
  * the policy itself is closed: default-src 'none', no unsafe-*;
  * the script contains no HTML-string sink, no dynamic code, no network call
    and no storage, and the only URL it can build is an ATT&CK technique page;
  * the markup has no inline handler, inline style, src or href, and the file is
    plain ASCII with LF line endings (no hidden or bidirectional characters);
  * guidance exists for every artifactClass the collectors can emit, and for
    nothing else, with no link in any entry;
  * the file mentions none of the words the repository must never contain.

`--seal` rewrites the policy hashes after a deliberate edit of the script or
the style; it changes nothing else. Usage:  check_viewer.py [--seal] [path]
"""
import base64, hashlib, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VIEWER = ROOT / "tools" / "viewer.html"
FIELDS = ("title", "ask", "look", "benign", "escalate")
SINKS = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(",
         "setTimeout(", "setInterval(", "fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon",
         "importScripts", "localStorage", "sessionStorage", "indexedDB", "createContextualFragment",
         "DOMParser", "srcdoc", "window.open", "location.", "javascript:", ".src ="]
# Assembled from parts so this gate does not itself contain the words it forbids.
FORBIDDEN_WORDS = re.compile(r"\b(%s)\b" % "|".join(["cl" + "aude", "anthr" + "opic", "ps" + "sa", "a" + "i"]), re.I)
ALLOWED_URL = "https://attack.mitre.org/techniques/"

problems = []
def fail(m): problems.append(m)

def b64(t): return "'sha256-" + base64.b64encode(hashlib.sha256(t.encode("utf-8")).digest()).decode() + "'"

def classes():
    ps1 = (ROOT / "Tatar.ps1").read_text(encoding="utf-8")
    m = re.search(r"\$script:ArtifactClasses\s*=\s*@\((.*?)\)", ps1, re.S)
    win = set(re.findall(r"'([a-z0-9-]+)'", m.group(1))) if m else set()
    sh = (ROOT / "linux" / "tatar-linux.sh").read_text(encoding="utf-8")
    m2 = re.search(r'^ARTIFACT_CLASSES="([^"]+)"', sh, re.M)
    lin = set(m2.group(1).split()) if m2 else set()
    return win, lin

def main(argv):
    seal = "--seal" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    path = Path(args[0]) if args else VIEWER
    if path.is_dir():
        path = path / "tools" / "viewer.html"
    if not path.is_file():
        print("usage: check_viewer.py [--seal] [path to viewer.html or to the repository]", file=sys.stderr)
        print("not found: %s" % path, file=sys.stderr)
        return 2
    raw = path.read_bytes()
    try: text = raw.decode("ascii")
    except UnicodeDecodeError as e:
        fail("viewer is not plain ASCII (byte %d): hidden or bidirectional characters are how a viewer lies to its reader" % e.start); text = raw.decode("utf-8", "replace")
    if b"\r" in raw: fail("viewer has CR characters: it must be LF so the hashes are the same on every checkout")

    styles = re.findall(r"<style>(.*?)</style>", text, re.S)
    scripts = re.findall(r"<script>(.*?)</script>", text, re.S)
    data = re.findall(r'<script type="application/json" id="guidance">(.*?)</script>', text, re.S)
    if len(styles) != 1: fail("expected exactly one <style>, found %d" % len(styles))
    if len(scripts) != 1: fail("expected exactly one executable <script>, found %d" % len(scripts))
    if len(data) != 1: fail("expected exactly one guidance data block, found %d" % len(data))
    if len(re.findall(r"<script", text)) != 2: fail("a <script> other than the code and the data block is present")
    if problems: return report()
    css, js = styles[0], scripts[0]

    m = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)">', text)
    if not m: fail("no Content-Security-Policy meta"); return report()
    csp = m.group(1)
    want = "default-src 'none'; script-src %s; style-src %s; img-src data:; base-uri 'none'; form-action 'none'" % (b64(js), b64(css))
    if csp != want:
        if seal:
            text = text.replace(csp, want); path.write_bytes(text.encode("ascii")); print("sealed: policy hashes updated"); csp = want
        else:
            fail("the policy does not match the file. Expected hashes: script %s, style %s. After a deliberate edit run: python .github/scripts/check_viewer.py --seal" % (b64(js), b64(css)))
    if "unsafe" in csp or "connect-src" in csp or "*" in csp: fail("policy is loosened: " + csp)

    for s in SINKS:
        if s in js: fail("script uses %r" % s)
    urls = set(re.findall(r"https?://[^'\"\s)]*", js))
    if urls != {ALLOWED_URL}: fail("script may contain only the ATT&CK technique URL prefix, found %s" % sorted(urls))
    markup = re.sub(r"<style>.*?</style>|<script[^>]*>.*?</script>", "", text, flags=re.S)
    for pat, what in ((r"\son[a-z]+\s*=", "inline event handler"), (r"\sstyle\s*=", "inline style attribute"),
                      (r"\ssrc\s*=", "src attribute"), (r"\shref\s*=", "href attribute"), (r"<link\b", "<link>"),
                      (r"<iframe|<object|<embed|<form\b", "embedding or form element"), (r"https?://", "URL in markup")):
        if re.search(pat, markup, re.I): fail("markup has a(n) " + what)
    if re.search(r"https?://", css): fail("style references a URL")
    if "url(" in css.replace("url(data:", ""): fail("style uses url()")

    try: g = json.loads(data[0])
    except Exception as e: fail("guidance is not valid JSON: %s" % e); return report()
    win, lin = classes()
    if not win: fail("could not read the Windows artifactClass set from Tatar.ps1")
    if not lin or not lin <= win: fail("Linux classes are not a subset of the Windows set: %s" % sorted(lin - win))
    if set(g) != win:
        fail("guidance and the collectors' closed artifactClass set differ. Missing: %s. Orphans: %s" % (sorted(win - set(g)), sorted(set(g) - win)))
    for k, v in g.items():
        if set(v) != set(FIELDS): fail("%s: fields must be exactly %s" % (k, list(FIELDS))); continue
        for f in FIELDS:
            x = v[f]
            if not isinstance(x, str) or not x.strip(): fail("%s.%s is empty" % (k, f))
            elif len(x) > 420: fail("%s.%s is %d characters; one line means one line" % (k, f, len(x)))
            elif "http" in x.lower() or "://" in x: fail("%s.%s contains a link: guidance names no URL and no download" % (k, f))
    m = FORBIDDEN_WORDS.search(text)
    if m: fail("forbidden word in the viewer: %r" % m.group(0))
    return report(len(g), len(lin))

def report(n=0, lin=0):
    if problems:
        for p in problems: print("FAIL  " + p)
        print("%d viewer problem(s)" % len(problems)); return 1
    print("OK: viewer policy sealed, no unsafe sink, guidance covers all %d artifact classes (%d on Linux)" % (n, lin)); return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
