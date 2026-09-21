import unittest
import tempfile
import time
import os
import threading
import urllib.request
import importlib.util
from pathlib import Path

# Load ups-monitor.py dynamically
spec = importlib.util.spec_from_file_location("ups_monitor", "ups-monitor.py")
ups_monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ups_monitor)


class TestDatabaseRetention(unittest.TestCase):
    def setUp(self):
        self.tmp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.tmp_db.close()
        self.db = ups_monitor.Database(Path(self.tmp_db.name))

    def tearDown(self):
        if os.path.exists(self.tmp_db.name):
            os.unlink(self.tmp_db.name)

    def test_stats_retention(self):
        now = time.time()
        # Insert old record manually
        with self.db.get_connection() as conn:
            conn.cursor().execute(
                "INSERT INTO stats (timestamp, status, charge, runtime, load, input_voltage, output_voltage, signal) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (now - 10 * 86400, "OL", 100, 3600, 15, 230, 230, None)
            )
            conn.commit()

        # Record a new stat with retention_days = 5
        self.db.record_stat("OL", 100, 3600, 15, 230, 230, retention_days=5)

        stats = self.db.get_latest_stats(10)
        # The 10-day old stat should have been deleted, leaving only 1
        self.assertEqual(len(stats), 1)

    def test_unlimited_retention(self):
        now = time.time()
        # Insert old record
        with self.db.get_connection() as conn:
            conn.cursor().execute(
                "INSERT INTO stats (timestamp, status, charge, runtime, load, input_voltage, output_voltage, signal) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (now - 100 * 86400, "OL", 100, 3600, 15, 230, 230, None)
            )
            conn.commit()

        # Record new stat with retention_days = 0 (unlimited)
        self.db.record_stat("OL", 100, 3600, 15, 230, 230, retention_days=0)

        stats = self.db.get_latest_stats(10)
        self.assertEqual(len(stats), 2)


class TestConfigValidation(unittest.TestCase):
    def test_valid_retention_days(self):
        cfg = yaml_helper_default_config()
        cfg["database"] = {"retention_days": 14}
        errors = ups_monitor.validate_config(cfg)
        self.assertEqual(errors, [])

    def test_invalid_retention_days(self):
        cfg = yaml_helper_default_config()
        cfg["database"] = {"retention_days": -5}
        errors = ups_monitor.validate_config(cfg)
        self.assertTrue(any("database.retention_days" in e for e in errors))


class TestImageRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = ups_monitor.Database(Path(tempfile.mktemp(suffix=".db")))
        default_cfg = yaml_helper_default_config()
        cls.controller = ups_monitor.UPSController(default_cfg, cls.db)

        ups_monitor.WebDashboardHandler.controller = cls.controller
        ups_monitor.WebDashboardHandler.db = cls.db

        cls.server = ups_monitor.ThreadedHTTPServer(("127.0.0.1", 0), ups_monitor.WebDashboardHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_netherlands_flag_image(self):
        url = f"http://127.0.0.1:{self.port}/img/netherlands.png"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Content-Type"), "image/png")
            content = resp.read()
            self.assertTrue(len(content) > 0)

    def test_uk_flag_image(self):
        url = f"http://127.0.0.1:{self.port}/img/uk.png"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Content-Type"), "image/png")
            content = resp.read()
            self.assertTrue(len(content) > 0)

    def test_nonexistent_image(self):
        url = f"http://127.0.0.1:{self.port}/img/nonexistent.png"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 404)
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)


def yaml_helper_default_config():
    import yaml
    return yaml.safe_load(ups_monitor.CONFIG_TEMPLATE)


if __name__ == "__main__":
    unittest.main()
