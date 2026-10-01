#!/usr/bin/env python3
"""Validate a TATAR collector output against its published JSON Schema.

Both CI jobs call THIS file so the two platforms can never be validated to
different standards: until v1.2.5 the Linux producer was schema-checked and the
Windows producer only had to parse as JSON.

    python3 .github/scripts/validate_summary.py <instance.json> <schema.json>

Beyond the schema it asserts the two promises a consumer actually relies on:
the count invariant (active + suppressed == findings) and, for a summary,
that every stats value is a number rather than a per-platform string.

Exit code: 0 = valid, 1 = invalid (message on stderr).
"""
import json
import sys

try:
    from jsonschema import validate
except ImportError:  # pragma: no cover - CI installs it explicitly
    sys.stderr.write("jsonschema is required: python3 -m pip install jsonschema\n")
    sys.exit(1)


def fail(msg):
    sys.stderr.write("FAIL: %s\n" % msg)
    sys.exit(1)


def main(argv):
    if len(argv) != 3:
        fail("usage: validate_summary.py <instance.json> <schema.json>")
    inst_path, schema_path = argv[1], argv[2]

    with open(inst_path, encoding="utf-8") as fh:
        inst = json.load(fh)
    with open(schema_path, encoding="utf-8") as fh:
        schema = json.load(fh)

    validate(instance=inst, schema=schema)

    findings = inst.get("findings")
    if not isinstance(findings, list):
        fail("findings must be a list, got %s" % type(findings).__name__)

    active, suppressed = inst.get("activeFindingsCount"), inst.get("suppressedCount")
    if inst.get("schemaVersion") != "1.1":
        for key in ("findingsCount", "activeFindingsCount", "suppressedCount"):
            if not isinstance(inst.get(key), int):
                fail("%s missing or not an integer: %r" % (key, inst.get(key)))
        if active + suppressed != len(findings):
            fail("active(%d) + suppressed(%d) != findings(%d)" % (active, suppressed, len(findings)))
        if inst.get("findingsCount") != len(findings):
            fail("findingsCount(%s) != findings(%d)" % (inst.get("findingsCount"), len(findings)))

    # A counter must be a number on every platform. The Linux collector used to
    # quote every stat, so a dashboard had to coerce string-vs-number per host.
    stats = inst.get("stats")
    if stats is not None:
        if not isinstance(stats, dict):
            fail("stats must be an object, got %s" % type(stats).__name__)
        numeric_strings = sorted(k for k, v in stats.items()
                                 if isinstance(v, str) and v.strip().lstrip("-").isdigit())
        if numeric_strings:
            fail("stats counters emitted as JSON strings: %s" % ", ".join(numeric_strings))
        canonical = schema.get("properties", {}).get("stats", {}).get("x-canonicalStatKeys")
        if canonical:
            unknown = sorted(k for k in stats if k not in canonical)
            if unknown:
                fail("stats key(s) not in the schema's x-canonicalStatKeys, so the "
                     "platforms have drifted apart again: %s" % ", ".join(unknown))

    skipped = inst.get("modulesSkipped")
    if skipped:
        fail("modulesSkipped is not empty - a requested module never ran: %s" % ", ".join(skipped))

    print("OK: %s validates against %s (schemaVersion %s, findings %d, active %s, suppressed %s)"
          % (inst_path, schema_path, inst.get("schemaVersion"), len(findings), active, suppressed))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
