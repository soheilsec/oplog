from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    operator TEXT NOT NULL,
    phase TEXT NOT NULL,
    asset TEXT,
    technique TEXT,
    summary TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    previous_hash TEXT,
    entry_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    event_id INTEGER,
    original_name TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    FOREIGN KEY(event_id) REFERENCES events(id)
);
CREATE TABLE IF NOT EXISTS deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    label TEXT NOT NULL,
    asset TEXT NOT NULL,
    build_sha256 TEXT,
    expires_at TEXT,
    cleanup_status TEXT NOT NULL DEFAULT 'pending',
    cleaned_at TEXT,
    cleaned_by TEXT
);
"""

SCOPE_TEMPLATE = """# Authorised targets only. Add one value per line.
targets:
  - host:example.internal
  - cidr:192.0.2.0/24
restrictions:
  - No actions outside approved targets.
approval_reference: CHANGE-ME
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def open_workspace(workspace: Path) -> sqlite3.Connection:
    database = workspace / "oplog.db"
    if not database.exists():
        raise FileNotFoundError(f"No OpLog workspace found at {workspace}")
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    return connection


def initialise(workspace: Path, name: str, vault_passphrase: str | None = None) -> None:
    if workspace.exists() and any(workspace.iterdir()):
        raise FileExistsError(f"Refusing to initialise a non-empty directory: {workspace}")
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "evidence" / "artifacts").mkdir(parents=True)
    (workspace / "reports").mkdir()
    (workspace / "scope.yml").write_text(SCOPE_TEMPLATE, encoding="utf-8")
    connection = sqlite3.connect(workspace / "oplog.db")
    connection.executescript(SCHEMA)
    connection.executemany(
        "INSERT INTO metadata(key, value) VALUES (?, ?)",
        [("engagement_name", name), ("created_at", utc_now())],
    )
    connection.commit()
    connection.close()
    if vault_passphrase is not None:
        from .vault import create_vault
        create_vault(workspace, vault_passphrase)


def scope_hash(workspace: Path) -> str:
    return sha256_file(workspace / "scope.yml")


def event_add(workspace: Path, operator: str, phase: str, asset: str | None, technique: str | None, summary: str) -> int:
    connection = open_workspace(workspace)
    previous = connection.execute("SELECT entry_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = previous["entry_hash"] if previous else ""
    created_at = utc_now()
    current_scope = scope_hash(workspace)
    payload = "|".join([created_at, operator, phase, asset or "", technique or "", summary, current_scope, previous_hash])
    entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    cursor = connection.execute(
        """INSERT INTO events(created_at, operator, phase, asset, technique, summary, scope_hash, previous_hash, entry_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (created_at, operator, phase, asset, technique, summary, current_scope, previous_hash or None, entry_hash),
    )
    connection.commit()
    connection.close()
    return cursor.lastrowid


def artifact_add(workspace: Path, source: Path, event_id: int | None) -> int:
    if not source.is_file():
        raise FileNotFoundError(f"Artifact does not exist: {source}")
    connection = open_workspace(workspace)
    if event_id is not None and not connection.execute("SELECT 1 FROM events WHERE id = ?", (event_id,)).fetchone():
        raise ValueError(f"Event EVT-{event_id:04d} does not exist")
    digest = sha256_file(source)
    stored_name = f"{digest[:12]}-{source.name}"
    destination = workspace / "evidence" / "artifacts" / stored_name
    if not destination.exists():
        shutil.copy2(source, destination)
    cursor = connection.execute(
        "INSERT INTO artifacts(created_at, event_id, original_name, stored_path, sha256) VALUES (?, ?, ?, ?, ?)",
        (utc_now(), event_id, source.name, str(destination.relative_to(workspace)), digest),
    )
    connection.commit()
    connection.close()
    return cursor.lastrowid


def deployment_add(workspace: Path, campaign: str, label: str, asset: str, build_hash: str | None, expires_at: str | None) -> int:
    connection = open_workspace(workspace)
    cursor = connection.execute(
        """INSERT INTO deployments(created_at, campaign_id, label, asset, build_sha256, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (utc_now(), campaign, label, asset, build_hash, expires_at),
    )
    connection.commit()
    connection.close()
    return cursor.lastrowid


def cleanup_attest(workspace: Path, deployment_id: int, operator: str, status: str) -> None:
    if status not in {"removed", "verified_absent", "not_required"}:
        raise ValueError("status must be removed, verified_absent, or not_required")
    connection = open_workspace(workspace)
    cursor = connection.execute(
        "UPDATE deployments SET cleanup_status = ?, cleaned_at = ?, cleaned_by = ? WHERE id = ?",
        (status, utc_now(), operator, deployment_id),
    )
    if cursor.rowcount != 1:
        raise ValueError(f"Deployment DEP-{deployment_id:04d} does not exist")
    connection.commit()
    connection.close()


def metadata(connection: sqlite3.Connection) -> dict[str, str]:
    return {row["key"]: row["value"] for row in connection.execute("SELECT key, value FROM metadata")}


def markdown_report(workspace: Path, kind: str) -> str:
    connection = open_workspace(workspace)
    info = metadata(connection)
    title = info.get("engagement_name", workspace.name)
    lines = [f"# {title} — {kind.title()} Report", "", f"Generated: {utc_now()}", ""]
    if kind == "timeline":
        lines += ["| ID | Time (UTC) | Phase | Asset | Technique | Summary |", "|---|---|---|---|---|---|"]
        for row in connection.execute("SELECT * FROM events ORDER BY id"):
            lines.append(f"| EVT-{row['id']:04d} | {row['created_at']} | {row['phase']} | {row['asset'] or '-'} | {row['technique'] or '-'} | {row['summary']} |")
    elif kind == "evidence":
        lines += ["| ID | File | SHA-256 | Linked event |", "|---|---|---|---|"]
        for row in connection.execute("SELECT * FROM artifacts ORDER BY id"):
            event = f"EVT-{row['event_id']:04d}" if row["event_id"] else "-"
            lines.append(f"| ART-{row['id']:04d} | {row['original_name']} | `{row['sha256']}` | {event} |")
    elif kind == "cleanup":
        lines += ["| ID | Campaign | Asset | Expiry | Cleanup status | Verified by |", "|---|---|---|---|---|---|"]
        for row in connection.execute("SELECT * FROM deployments ORDER BY id"):
            lines.append(f"| DEP-{row['id']:04d} | {row['campaign_id']} | {row['asset']} | {row['expires_at'] or '-'} | {row['cleanup_status']} | {row['cleaned_by'] or '-'} |")
    else:
        raise ValueError("report kind must be timeline, evidence, or cleanup")
    connection.close()
    return "\n".join(lines) + "\n"


def status(workspace: Path) -> dict[str, object]:
    from .vault import vault_fingerprint
    connection = open_workspace(workspace)
    info = metadata(connection)
    result = {
        "engagement": info.get("engagement_name", workspace.name),
        "events": connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "artifacts": connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0],
        "deployments": connection.execute("SELECT COUNT(*) FROM deployments").fetchone()[0],
        "pending_cleanup": connection.execute("SELECT COUNT(*) FROM deployments WHERE cleanup_status = 'pending'").fetchone()[0],
        "scope_sha256": scope_hash(workspace),
        "vault_present": vault_fingerprint(workspace) is not None,
    }
    connection.close()
    return result
