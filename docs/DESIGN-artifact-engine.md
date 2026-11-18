# Design: declarative artifacts and packs

Status: design only, not implemented. Written down so the work can start from a
fixed set of constraints instead of from a blank page.

## Why

Every collector today is code. Adding "read this file and flag lines that match
X" means editing a 3,000-line script, and a pull request that has to be
reviewed as code. A declarative layer would let an analyst add a check as data,
reviewed as data. The risk is the opposite of the benefit: a definition
language that can run commands or read arbitrary hosts' files turns a read-only
collector into a remote-execution surface and brings back the antivirus
problem this project avoids.

## Constraints (non-negotiable, taken from the existing principles)

1. Read-only, offline, standard user. A definition can only name something to
   read; it cannot run a program, write, or reach the network.
2. Not Turing-complete. No loops, variables or expressions in a definition;
   matching is a fixed set of operators (equals, contains, regex with a length
   and time bound, numeric compare).
3. Same output contract. A definition produces findings with the same fields
   (including `fingerprint`, `contentHash`, `evidence[]`) and a `module` of
   `artifact:<name>`; nothing new for consumers to learn.
4. Same safety nets. Every definition is subject to the existing control-
   character, CSV-cell and size limits, and its reads are bounded.
5. Same on both editions, or explicitly marked single-platform.
6. Verifiable. A pack is a folder of JSON files plus a SHA-256 manifest; a pack
   whose manifest does not match is not loaded.

## Source types (the closed set)

`file` (path glob, bounded bytes), `registry_value` and `registry_key`
(Windows), `directory_listing`, `file_hash` (SHA-256 of a named file),
`wmi_query` (Windows, a fixed allowlist of read-only classes), `command_output`
is deliberately absent. Interoperability target: definitions loadable from, and
exportable to, the ForensicArtifacts YAML/JSON vocabulary for the sources above.

## Definition sketch

    { "name": "SuspiciousRunKeyValue",
      "doc": "Run key value pointing into a user-writable folder",
      "sources": [ { "type": "registry_value", "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" } ],
      "match":   [ { "field": "data", "op": "regex", "value": "(?i)\\\\appdata\\\\" } ],
      "finding": { "severity": "Review", "category": "Persistence", "artifactClass": "run-key",
                   "message": "Run value points into AppData" } }

`artifactClass` must be one of the existing closed vocabulary; a pack cannot
invent a class.

## Packs

A pack is a named, versioned set of definitions for one purpose (for example
"ransomware precursors", "webshell leads", "RMM tools"). `-Pack name` selects
it. Packs are data, so they can be reviewed, signed and shared independently of
the collector release.

## Order of work

1. Loader + validator for the definition schema (JSON Schema, no execution).
2. `file` and `registry_value` sources only, with the matching operators, on
   one edition; golden-vector tests as for the fingerprint.
3. Port to the other edition and add the remaining source types one at a time,
   each with a test that proves it cannot read outside its stated scope.
4. Pack manifest verification.
5. Only then: ForensicArtifacts import/export.

## Not goals

Fleet orchestration, remote execution, a query language, a plugin system that
loads code. Those belong to other tools; this one stays a read-only triage
collector with a verifiable output.
