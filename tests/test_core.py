import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oplog.core import artifact_add, cleanup_attest, deployment_add, event_add, initialise, markdown_report, status
from oplog.vault import add_secret, get_secret, list_secrets


class OpLogTests(unittest.TestCase):
    def test_end_to_end_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "demo"
            initialise(workspace, "Demo engagement")
            event_id = event_add(workspace, "soheil", "discovery", "host:example.internal", "T1595", "Approved observation recorded.")
            source = Path(temporary) / "evidence.txt"
            source.write_text("test evidence", encoding="utf-8")
            artifact_add(workspace, source, event_id)
            deployment = deployment_add(workspace, "RT-001", "approved tooling", "host:example.internal", "a" * 64, "2026-10-01")
            cleanup_attest(workspace, deployment, "soheil", "removed")
            self.assertIn("EVT-0001", markdown_report(workspace, "timeline"))
            self.assertIn("ART-0001", markdown_report(workspace, "evidence"))
            self.assertIn("removed", markdown_report(workspace, "cleanup"))
            self.assertEqual(status(workspace)["pending_cleanup"], 0)

    def test_vault_is_separate_from_public_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "vault-demo"
            initialise(workspace, "Vault demo", "correct horse battery staple")
            secret_id = add_secret(workspace, "correct horse battery staple", "token", "test token", "value-not-in-ledger", None, None)
            self.assertEqual(list_secrets(workspace, "correct horse battery staple")[0]["label"], "test token")
            self.assertEqual(get_secret(workspace, "correct horse battery staple", secret_id)["value"], "value-not-in-ledger")
            self.assertNotIn("value-not-in-ledger", (workspace / "oplog.db").read_bytes().decode("latin1"))
            self.assertNotIn("value-not-in-ledger", (workspace / "vault.oplog").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
