# HTB Pirate — OpLog exercise

This example maps the public HTB Pirate storyline into an engagement ledger.
It is intentionally sanitised: no credentials, hashes, tickets, challenge
responses, flags, or executable attack commands are written to the workspace.

Create it after installing OpLog:

```bash
python examples/pirate_demo.py pirate-oplog-demo
cd pirate-oplog-demo
python -m oplog status
```

The generated timeline records thirteen material milestones: initial service
reconnaissance, supplied-account validation, directory relationship collection,
legacy account exposure, managed service account access, internal routing,
relay-path validation, elevated access validation, impact and cleanup. The
evidence files are synthetic summaries so that the example remains safe to
publish.

## What the current MVP proves

- Each material action has a time, operator, asset, technique tag and scope
  hash.
- Each artifact is copied into the workspace and bound to an event by SHA-256.
- The generated reports can be reconstructed from `oplog.db`.
- A temporary operator-artifact inventory appears in the cleanup report.

## What Pirate exposes as missing

The example also makes the limits obvious:

1. **Assets and identities are just strings.** There is no inventory or
   relationship graph for DC01, WEB01, accounts, groups and services.
2. **No observation/hypothesis/finding model exists.** A timeline entry cannot
   distinguish an unconfirmed lead from a verified control failure.
3. **No change register exists.** A state-changing validation needs before/after
   evidence, approval, owner and rollback verification; a deployment row is not
   enough.
4. **Scope is hashed but not evaluated.** The tool cannot yet identify that a
   new internal address is outside the approved CIDR.
5. **No collection-run provenance exists.** A graph export or Nmap XML is an
   artifact, but OpLog cannot yet record tool version, collection parameters,
   coverage and result summary.

Those five gaps are the next product work. Do not add a web UI, scanner runner
or credential store before addressing them.
