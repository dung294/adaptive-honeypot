import unittest
import json
import shutil
from pathlib import Path
from threat_intel.ml_exporter import (
    MLLogExporter,
    redact_sensitive_data,
    SCENARIOS_CATALOG
)

class TestMLExporter(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path("data/raw/test-run-ml-001")
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

        self.exporter = MLLogExporter(
            run_id="test-run-ml-001",
            campaign_id="test-camp-001",
            dataset_role="train",
            output_base_dir=Path("data/raw")
        )

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_redact_sensitive_data(self):
        """Kiểm tra loại bỏ mật khẩu và token nhạy cảm."""
        text = "ssh -p 22 root@host --password 'SuperSecretPass123!'"
        redacted = redact_sensitive_data(text)
        self.assertNotIn("SuperSecretPass123!", redacted)
        self.assertIn("[REDACTED]", redacted)

        text2 = "curl -H 'Authorization: Bearer my_secret_token_123456789' http://c2"
        redacted2 = redact_sensitive_data(text2)
        self.assertNotIn("my_secret_token_123456789", redacted2)
        self.assertIn("[REDACTED_TOKEN]", redacted2)

    def test_session_lifecycle_and_schema(self):
        """Kiểm tra đầy đủ vòng đời: login -> command -> session_closed."""
        sess_id = "session-test-100"
        ip = "192.168.56.50"
        port = 54321

        # 1. Login
        evt_login = self.exporter.emit_login(sess_id, ip, port, "root", "ssh-discovery-001")
        self.assertEqual(evt_login["event_status"], "login")
        self.assertEqual(evt_login["protocol"], "ssh")
        self.assertTrue(evt_login["timestamp"].endswith("Z"))

        # 2. Command
        evt_cmd = self.exporter.emit_command(
            sess_id, ip, port, "root", "whoami", "root", "ssh-discovery-001"
        )
        self.assertEqual(evt_cmd["event_status"], "command")
        self.assertEqual(evt_cmd["command"], "whoami")
        self.assertEqual(evt_cmd["command_output"], "root")

        # 3. Session Closed
        evt_close = self.exporter.emit_session_closed(sess_id, ip, port, "root", "ssh-discovery-001")
        self.assertEqual(evt_close["event_status"], "session_closed")

        # 4. Finalize Run
        summary = self.exporter.finalize_run()
        self.assertEqual(summary["total_events"], 3)

        # Kiểm tra file events.jsonl
        events_file = Path(summary["events_file"])
        self.assertTrue(events_file.exists())
        with open(events_file, "r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[-1]["event_status"], "session_closed")

        # Kiểm tra run_manifest.json
        run_manifest_file = Path(summary["run_manifest_file"])
        self.assertTrue(run_manifest_file.exists())
        with open(run_manifest_file, "r", encoding="utf-8") as f:
            run_manifest = json.load(f)
        self.assertEqual(run_manifest["run_id"], "test-run-ml-001")
        self.assertEqual(run_manifest["dataset_role"], "train")
        self.assertIn("ssh-discovery-001", run_manifest["scenario_id"])

        # Kiểm tra scenario_manifest.json (Ground Truth)
        scen_manifest_file = Path(summary["scenario_manifest_file"])
        self.assertTrue(scen_manifest_file.exists())
        with open(scen_manifest_file, "r", encoding="utf-8") as f:
            scen_manifest = json.load(f)
        self.assertEqual(len(scen_manifest), 1)
        self.assertEqual(scen_manifest[0]["ground_truth_label"], SCENARIOS_CATALOG["ssh-discovery-001"]["ground_truth_label"])

if __name__ == "__main__":
    unittest.main()
