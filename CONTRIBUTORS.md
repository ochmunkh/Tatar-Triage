# Contributors

TATAR Triage Toolkit is maintained by **Enkhbat.O**.

The people below have contributed code, review or documentation. Order is by
first contribution.

| Contributor | Contribution |
|---|---|
| [Enkhbat.O](https://github.com/ochmunkh) | Author and maintainer |
| [Yalguun Tumenkhuu](https://github.com/fg0x0) | v1.3.0 — review and hardening of both collectors: the evidence manifest, argument parsing, the `summary.json` contract, the static review of the 18 Windows-only modules, cross-edition parity checks in CI, and the Mongolian halves of the README, the Linux README and the ATT&CK mapping |

## Adding yourself

A merged pull request earns a row here. Add it in the same PR, or ask and the
maintainer will. Use the name and profile you want associated with the work.

Reporting a vulnerability earns credit in `CHANGELOG.md` for the release that
fixes it, unless you ask otherwise — see [`SECURITY.md`](SECURITY.md).

## Before you fork or open a pull request

Read the architectural invariants in [`CONTRIBUTING.md`](CONTRIBUTING.md). Most
of this tool is open to change; a short list of things is not, because each of
them is a way this collector could quietly stop being a triage tool — fast,
privilege-light and read-only on a host that may already be compromised.
