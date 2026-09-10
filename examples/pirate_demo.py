"""Create a sanitised OpLog workspace based on HTB Pirate's public storyline. (https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)

This is a lab demonstration, not an exploitation script. It deliberately does
not save passwords, hashes, tickets, commands that contain secrets, or flags.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from oplog.core import artifact_add, cleanup_attest, deployment_add, event_add, initialise, markdown_report


EVENTS = [
    ("discovery", "host:DC01.pirate.htb", "T1595", "Documented exposed services and identified the domain controller role."),
    ("validation", "identity:pirate\\pentest", "T1078", "Validated the supplied lab account without recording its secret."),
    ("discovery", "domain:pirate.htb", "T1087", "Collected directory relationship data and recorded an offline graph artifact."),
    ("discovery", "identity:MS01$", "T1558", "Observed a legacy machine-account exposure path; sensitive authentication material was excluded from OpLog."),
    ("validation", "identity:gMSA_ADFS_prod$", "T1552", "Validated an over-broad managed-service-account password-read relationship in the lab."),
    ("access", "host:DC01.pirate.htb", "T1021.006", "Verified authorised remote administrative access to the domain controller."),
    ("discovery", "network:192.168.100.0/24", "T1018", "Documented the internal segment and the route required to reach WEB01."),
    ("validation", "host:WEB01.pirate.htb", "T1557", "Recorded an authentication-relay exposure on the internal host; no capture material was stored."),
    ("access", "host:WEB01.pirate.htb", "T1550.003", "Verified elevated access after the authorised delegation-path validation."),
    ("discovery", "identity:a.white", "T1552.004", "Recorded discovery of an autologon credential exposure; secret values were excluded."),
    ("validation", "identity:a.white_adm", "T1098", "Documented an excessive password-reset relationship and constrained-delegation attack path."),
    ("reporting", "domain:pirate.htb", "", "Captured impact evidence and prepared the timeline and evidence register."),
    ("cleanup", "host:WEB01.pirate.htb", "T1070", "Verified lab-only changes and temporary operator artifacts were removed."),
]

ARTIFACTS = {
    "recon-summary.txt": "Sanitised recon summary: domain controller and exposed service observations recorded.\n",
    "directory-relationship-notes.txt": "Sanitised directory relationship notes: legacy machine-account and managed-service-account risk paths observed.\n",
    "internal-route-notes.txt": "Sanitised network route notes: an internal web-server segment was reachable through the authorised lab path.\n",
    "impact-and-cleanup.txt": "Sanitised impact and cleanup record: no credential material, flags, tickets or challenge-response data retained.\n",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a sanitised HTB Pirate OpLog demonstration")
    parser.add_argument("workspace", type=Path, help="new, empty destination directory")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    initialise(workspace, "HTB Pirate — sanitised lab demonstration")
    (workspace / "scope.yml").write_text(
        "targets:\n  - host:DC01.pirate.htb\n  - host:WEB01.pirate.htb\nrestrictions:\n  - HTB lab only; do not store secrets, flags, tickets, or captured authentication material.\napproval_reference: HTB-PIRATE-LAB\n",
        encoding="utf-8",
    )
    source_dir = workspace / "demo-source"
    source_dir.mkdir()
    event_ids = []
    for phase, asset, technique, summary in EVENTS:
        event_ids.append(event_add(workspace, "operator", phase, asset, technique or None, summary))
    for index, (name, content) in enumerate(ARTIFACTS.items()):
        source = source_dir / name
        source.write_text(content, encoding="utf-8")
        artifact_add(workspace, source, event_ids[min(index * 3, len(event_ids) - 1)])
    deployment_id = deployment_add(
        workspace,
        campaign="HTB-PIRATE-LAB",
        label="temporary operator artefact inventory",
        asset="host:WEB01.pirate.htb",
        build_hash=None,
        expires_at="lab-end",
    )
    cleanup_attest(workspace, deployment_id, "operator", "removed")
    for kind in ("timeline", "evidence", "cleanup"):
        (workspace / "reports" / f"{kind}.md").write_text(markdown_report(workspace, kind), encoding="utf-8")
    print(f"Created demo workspace: {workspace}")
    print("Review reports/timeline.md, reports/evidence.md, and reports/cleanup.md.")


if __name__ == "__main__":
    main()
