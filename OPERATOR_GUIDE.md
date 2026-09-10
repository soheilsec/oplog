OpLog Operator Guide
Version: 0.2.0  
Audience: authorised Red Team, penetration-test, and purple-team operators  
Operating model: local-first, single-operator engagement ledger
1. Purpose and boundaries
OpLog records an authorised engagement from kickoff through cleanup. It keeps
the report-safe operational ledger separate from an encrypted operator vault.
Use it to preserve context, evidence provenance, scope history, and cleanup
status while the work is happening.
OpLog does not execute scans, exploitation, C2 actions, credential abuse,
or remote commands. Run approved tools separately, then record the material
action and attach the resulting artifact.
Only use OpLog within an approved Rules of Engagement (RoE). Do not place
customer secrets in the public SQLite ledger, public evidence folder, terminal
history, Markdown reports, or command-line arguments.
2. Data separation
Location	Purpose	May contain secret values?	Included in reports?
`oplog.db`	Events, artifact metadata, deployment and cleanup metadata	No	Indirectly
`evidence/artifacts/`	Copied, report-safe evidence files	No	Yes, by reference
`vault.oplog`	Encrypted operator-only passwords, hashes, tickets, tokens, keys and short notes	Yes	No
`scope.yml`	Approved targets, restrictions and approval reference	No	No
`reports/`	Generated Markdown timeline, evidence, and cleanup outputs	No	Yes
`vault.oplog` uses AES-256-GCM encryption. Its key is derived from the
passphrase using scrypt and a unique random salt. The passphrase is not
recoverable by OpLog.
3. Installation
From the OpLog source directory:
```cmd
python -m pip install -e .
oplog --help
```
You may use either `oplog ...` or `python -m oplog ...` after installation.
4. Start an engagement
Create a named workspace. OpLog prompts twice for a Vault passphrase by
default.
```cmd
oplog init acme-q3 --name "Acme Q3 authorised internal assessment"
cd acme-q3
```
The workspace contains:
```text
acme-q3/
├── evidence/artifacts/
├── reports/
├── oplog.db
├── scope.yml
└── vault.oplog
```
Inside the workspace, `--workspace` is optional. From outside it, pass the
workspace explicitly, for example `--workspace acme-q3`.
4.1 Define the scope
Edit `scope.yml` before recording activity:
```yaml
targets:
  - cidr:10.20.30.0/24
  - host:portal.acme.example
  - app:https://portal.acme.example
restrictions:
  - Production testing is limited to the approved window.
  - No denial-of-service testing.
approval_reference: ACME-CHG-2026-014
```
Record a kickoff event after scope approval:
```cmd
oplog event add --operator soheil --phase discovery --asset engagement:acme-q3 --summary "RoE, approved targets, testing window, and escalation contacts were reviewed."
```
OpLog 0.2.0 hashes the active `scope.yml` for each event. It does not yet
parse CIDRs or automatically block an out-of-scope target; the operator must
validate scope before every material action.
5. Record activity consistently
Every material action should create one concise event. Use the following
phases:
Phase	Use for
`discovery`	Reconnaissance, asset discovery, service and identity observations
`validation`	Confirming a suspected exposure or control weakness
`access`	Authorised access verification or a confirmed access milestone
`post_access`	Privilege, lateral-movement, collection, or impact validation milestones
`reporting`	Evidence review, finding validation, report drafting
`cleanup`	Removal, restoration, expiry verification, and handover
Use an `asset` that is stable and readable, such as `cidr:10.20.30.0/24`,
`host:ws-014.acme.example`, `identity:ACME\\svc-api`, or
`app:https://portal.acme.example`.
Use a MITRE ATT&CK reference when it adds useful context:
```cmd
oplog event add --operator soheil --phase discovery --asset cidr:10.20.30.0/24 --technique T1595 --summary "Recorded the approved baseline network collection and retained its report-safe output."
```
Good summaries state what was done or observed, where, and why it
matters. They do not contain passwords, commands with secrets, flag values,
cookie values, raw tickets, authentication responses, or private keys.
6. Attach scan and discovery artifacts
Run an approved collection tool outside OpLog. Store a report-safe copy of the
result, then bind it to the event that describes the collection. OpLog copies
the file into the workspace and records a SHA-256 checksum.
6.1 IP range scan output
For an approved range scan output saved as `internal-baseline.xml`:
```cmd
oplog artifact add C:\Engagement\scans\internal-baseline.xml --event 2
```
For a text or Markdown service summary:
```cmd
oplog artifact add C:\Engagement\notes\service-summary.md --event 2
```
6.2 Web and API discovery/fuzzing output
Create a separate event for the approved web collection, then attach its
result. A JSON output, Burp export, or redacted HTTP evidence is acceptable if
it does not contain live session tokens or credentials.
```cmd
oplog event add --operator soheil --phase discovery --asset app:https://portal.acme.example --technique T1595.002 --summary "Recorded approved web content and API surface discovery output."

oplog artifact add C:\Engagement\web\content-discovery.json --event 3
oplog artifact add C:\Engagement\web\redacted-request-response.md --event 3
```
6.3 Current limitation
OpLog 0.2.0 stores and hashes Nmap, ffuf, Burp, BloodHound, Certipy, Nessus
and similar exports, but does not parse them yet. The next importer feature
should create asset and service observations while retaining the original
artifact as provenance.
7. Attach screenshots and evidence
Use screenshots for material proof: confirmation of access level, affected
asset, before/after state, user-visible impact, remediation validation, and
cleanup verification.
Before attaching a screenshot:
Crop unrelated desktop content.
Redact passwords, hashes, tokens, tickets, cookies, private keys, personal
data, client data, and unrelated hostnames.
Keep enough context to show host, identity, timestamp or application state.
Use a clear filename, for example `WEB01-admin-context-redacted.png`.
Then attach it to the relevant event:
```cmd
oplog artifact add C:\Engagement\screenshots\WEB01-admin-context-redacted.png --event 8
```
The evidence report provides the artifact ID, event link, filename, and
SHA-256. The copied file is located under `evidence/artifacts/`.
8. Store passwords, hashes, tickets, and tokens in the Vault
The Vault is for short, sensitive values needed by the operator during the
engagement. It is not part of the final report.
8.1 Add a password
```cmd
oplog vault add --type password --label "ACME temporary assessment account" --event 4 --expires 2026-10-01
```
OpLog asks for the secret value through a hidden prompt and then requests the
Vault passphrase. Never place the value after the command or paste it into an
event summary.
8.2 Add a hash, ticket, token, or private key
```cmd
oplog vault add --type hash --label "ACME service-account hash" --event 5
oplog vault add --type ticket --label "ACME authorised Kerberos test ticket" --event 6 --expires 2026-10-01
oplog vault add --type token --label "ACME test API token" --event 7 --expires 2026-10-01
oplog vault add --type private_key --label "ACME temporary assessment key" --event 7
```
Supported types are `password`, `hash`, `ticket`, `token`, `private_key`, and
`note`.
8.3 List and reveal Vault entries
```cmd
oplog vault list
oplog vault show 1 --reveal
```
`vault list` displays labels and metadata only. `vault show` requires the
explicit `--reveal` flag and the passphrase.
8.4 Sensitive raw artifacts
Do not use `oplog artifact add` for terminal output containing secrets,
ticket files, browser profiles, credential dumps, private keys, or raw
authentication captures. OpLog 0.2.0 encrypts short Vault values only; an
encrypted Vault-artifact command is not implemented yet. Store those files in
the approved client-controlled evidence repository or an approved encrypted
container outside the public OpLog evidence folder, and record only a redacted
reference event in OpLog.
9. Track deployment and cleanup obligations
When an approved temporary operator artifact, configuration change, or other
cleanup-requiring item exists, create a manifest row. Use the build checksum
where available.
```cmd
oplog manifest record-deployment --campaign ACME-RT-2026-014 --label "temporary operator artefact" --asset host:ws-014.acme.example --build-sha256 <sha256> --expires 2026-10-01
```
After removal or verification:
```cmd
oplog manifest cleanup --deployment 1 --operator soheil --status removed
```
Allowed cleanup statuses are `removed`, `verified_absent`, and `not_required`.
Also record a cleanup event:
```cmd
oplog event add --operator soheil --phase cleanup --asset host:ws-014.acme.example --summary "Temporary operator artefact was removed and cleanup was verified."
```
10. Generate end-of-engagement outputs
From inside the workspace:
```cmd
oplog status
oplog report timeline --out reports\timeline.md
oplog report evidence --out reports\evidence.md
oplog report cleanup --out reports\cleanup.md
```
Output	Use
`timeline.md`	Chronological operator record for internal QA and report drafting
`evidence.md`	Artifact register with integrity hashes and linked events
`cleanup.md`	Deployment inventory and cleanup status
Review the files before sharing. These reports intentionally exclude Vault
values. Write the client-facing findings report from the validated evidence,
not from raw terminal transcripts.
11. Recommended engagement cadence
Create the workspace and Vault; review `scope.yml`.
Record the kickoff and each approved collection run.
Add report-safe outputs and screenshots immediately after collection.
Store only necessary sensitive values in the Vault, with source event and
expiry where applicable.
Record each material validation, access, post-access, impact, and change.
Register every temporary artefact or change that requires removal.
Generate interim reports before handover and resolve missing evidence.
Complete cleanup, attest it in the manifest, and record the final cleanup
event.
Generate final reports and archive the workspace according to the RoE and
client retention requirements.
12. Quick troubleshooting
Problem	Resolution
`No OpLog workspace found`	`cd` into the workspace, or pass the correct `--workspace` path.
`Artifact does not exist`	Use the path relative to your current directory, or provide the full path.
`No vault entries`	The Vault exists but no secret has been added yet; use `oplog vault add`.
`Vault could not be opened`	Confirm the passphrase. A forgotten passphrase cannot be recovered.
`report ... requires kind`	Use `oplog report timeline --out reports\timeline.md`; the report kind comes first.
13. Product roadmap suggested by real engagements
Encrypted Vault artifacts for sensitive raw outputs.
Scope parsing and out-of-scope warnings.
Asset, identity, service, and relationship inventory.
Observation, hypothesis, finding, and impact data model.
Change register with before/after evidence, rollback and approval fields.
Read-only importers for Nmap XML, web-fuzz JSON, BloodHound and Certipy exports.
Tamper-evident chain verification and signed handover bundles.
