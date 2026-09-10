from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path

from . import __version__
from .core import artifact_add, cleanup_attest, deployment_add, event_add, initialise, markdown_report, status
from .vault import add_secret, get_secret, list_secrets


def workspace_path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def add_workspace_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--workspace",
        type=workspace_path,
        default=Path.cwd().resolve(),
        help="workspace path (defaults to the current directory)",
    )


def prompt_passphrase(confirm: bool = False) -> str:
    value = getpass.getpass("Vault passphrase: ")
    if not value:
        raise ValueError("Vault passphrase cannot be empty")
    if confirm and value != getpass.getpass("Confirm vault passphrase: "):
        raise ValueError("Vault passphrases did not match")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oplog",
        description="Offline ledger for authorised security engagements — created by Soheil Hashemi (github.com/soheilsec)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__} | Soheil Hashemi | github.com/soheilsec")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create a new engagement workspace")
    init.add_argument("workspace", type=workspace_path)
    init.add_argument("--name", required=True)
    init.add_argument("--no-vault", action="store_true", help="create a public-ledger-only workspace")

    event = commands.add_parser("event", help="Record an append-only engagement event")
    event_sub = event.add_subparsers(dest="event_command", required=True)
    add = event_sub.add_parser("add")
    add_workspace_argument(add)
    add.add_argument("--operator", required=True)
    add.add_argument("--phase", required=True, choices=["discovery", "validation", "access", "post_access", "reporting", "cleanup"])
    add.add_argument("--asset")
    add.add_argument("--technique")
    add.add_argument("--summary", required=True)

    artifact = commands.add_parser("artifact", help="Store and hash an evidence artifact")
    artifact_sub = artifact.add_subparsers(dest="artifact_command", required=True)
    add = artifact_sub.add_parser("add")
    add.add_argument("source", type=Path)
    add_workspace_argument(add)
    add.add_argument("--event", type=int)

    manifest = commands.add_parser("manifest", help="Track authorised deployment and cleanup metadata")
    manifest_sub = manifest.add_subparsers(dest="manifest_command", required=True)
    deploy = manifest_sub.add_parser("record-deployment")
    add_workspace_argument(deploy)
    deploy.add_argument("--campaign", required=True)
    deploy.add_argument("--label", required=True)
    deploy.add_argument("--asset", required=True)
    deploy.add_argument("--build-sha256")
    deploy.add_argument("--expires")
    cleanup = manifest_sub.add_parser("cleanup")
    add_workspace_argument(cleanup)
    cleanup.add_argument("--deployment", required=True, type=int)
    cleanup.add_argument("--operator", required=True)
    cleanup.add_argument("--status", required=True, choices=["removed", "verified_absent", "not_required"])

    report = commands.add_parser("report", help="Generate a Markdown report")
    report.add_argument("kind", choices=["timeline", "evidence", "cleanup"])
    add_workspace_argument(report)
    report.add_argument("--out", required=True, type=Path)

    state = commands.add_parser("status", help="Show workspace summary")
    add_workspace_argument(state)

    vault = commands.add_parser("vault", help="Manage encrypted operator-only secrets")
    vault_sub = vault.add_subparsers(dest="vault_command", required=True)
    add = vault_sub.add_parser("add", help="Store a secret in the encrypted vault")
    add_workspace_argument(add)
    add.add_argument("--type", required=True, choices=["password", "hash", "ticket", "token", "private_key", "note"])
    add.add_argument("--label", required=True)
    add.add_argument("--event", type=int)
    add.add_argument("--expires")
    listing = vault_sub.add_parser("list", help="List vault metadata without revealing values")
    add_workspace_argument(listing)
    show = vault_sub.add_parser("show", help="Reveal one secret after an explicit confirmation")
    add_workspace_argument(show)
    show.add_argument("secret", type=int)
    show.add_argument("--reveal", action="store_true", help="required to print the secret value")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "init":
            passphrase = None if args.no_vault else prompt_passphrase(confirm=True)
            initialise(args.workspace, args.name, passphrase)
            print(f"Created OpLog workspace: {args.workspace}")
        elif args.command == "event":
            identifier = event_add(args.workspace, args.operator, args.phase, args.asset, args.technique, args.summary)
            print(f"Recorded EVT-{identifier:04d}")
        elif args.command == "artifact":
            identifier = artifact_add(args.workspace, args.source, args.event)
            print(f"Stored ART-{identifier:04d}")
        elif args.command == "manifest" and args.manifest_command == "record-deployment":
            identifier = deployment_add(args.workspace, args.campaign, args.label, args.asset, args.build_sha256, args.expires)
            print(f"Recorded DEP-{identifier:04d}")
        elif args.command == "manifest":
            cleanup_attest(args.workspace, args.deployment, args.operator, args.status)
            print(f"Updated DEP-{args.deployment:04d}")
        elif args.command == "report":
            content = markdown_report(args.workspace, args.kind)
            output = args.out if args.out.is_absolute() else args.workspace / args.out
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")
            print(f"Wrote {output}")
        elif args.command == "vault" and args.vault_command == "add":
            secret = getpass.getpass("Secret value (hidden): ")
            identifier = add_secret(args.workspace, prompt_passphrase(), args.type, args.label, secret, args.event, args.expires)
            print(f"Stored SEC-{identifier:04d} in encrypted vault")
        elif args.command == "vault" and args.vault_command == "list":
            entries = list_secrets(args.workspace, prompt_passphrase())
            for entry in entries:
                event = f"EVT-{entry['source_event']:04d}" if entry["source_event"] else "-"
                print(f"SEC-{entry['id']:04d}  {entry['type']:<11}  {entry['label']}  event={event}  status={entry['status']}")
            if not entries:
                print("No vault entries.")
        elif args.command == "vault":
            if not args.reveal:
                parser.error("vault show requires --reveal; use vault list for metadata")
            item = get_secret(args.workspace, prompt_passphrase(), args.secret)
            print(item["value"])
        else:
            print(json.dumps(status(args.workspace), indent=2))
    except (FileExistsError, FileNotFoundError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
