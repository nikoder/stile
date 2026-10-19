# Security policy

stile is an authentication gate — reports about its security are the most
valuable contributions it can receive.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** via GitHub's
["Report a vulnerability"](../../security/advisories/new) form (the
Security tab of this repository). Reports arrive as confidential draft
advisories visible only to the maintainer, with a private thread for
discussion.

Please do **not** open a public issue for anything you believe is
exploitable. If you can't use the private form (no GitHub account), open a
regular issue saying only that you'd like a private channel — include no
details — and one will be arranged.

This is a spare-time project; best effort is a response within a week.

## Scope notes for reporters

The [threat model](README.md#threat-model--read-this-before-using-it) is
deliberate and documented: presence-only assertions (no PIN/UV), accepted
physical-theft trade-offs, and the freeze mechanism as the stolen-key
remediation. Reports that the documented trade-offs exist won't be treated
as vulnerabilities — reports that the implementation fails to deliver what
the documentation promises absolutely will.
