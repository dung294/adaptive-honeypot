import unittest
from gateway.web_decoy import app, simulate_rce_cmd

class TestWebDecoy(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_normal_ping(self):
        res = self.client.get("/ping?host=127.0.0.1")
        self.assertEqual(res.status_code, 200)
        self.assertIn("PING 127.0.0.1", res.get_data(as_text=True))

    def test_rce_whoami(self):
        res = self.client.get("/ping?host=127.0.0.1;whoami")
        self.assertEqual(res.status_code, 200)
        data = res.get_data(as_text=True)
        self.assertIn("www-data", data)

    def test_rce_leak_credentials(self):
        res = self.client.get("/ping?host=127.0.0.1;cat%20.env")
        self.assertEqual(res.status_code, 200)
        data = res.get_data(as_text=True)
        self.assertIn("SSH_PORT=2222", data)
        self.assertIn("SSH_USER=ubuntu", data)
        self.assertIn("SSH_PASSWORD=supersecretpassword123", data)

    def test_rce_etc_passwd(self):
        res = self.client.get("/ping?host=127.0.0.1;cat%20/etc/passwd")
        self.assertEqual(res.status_code, 200)
        data = res.get_data(as_text=True)
        self.assertIn("root:x:0:0", data)
        self.assertIn("ubuntu:x:1000:1000", data)

if __name__ == "__main__":
    unittest.main()
