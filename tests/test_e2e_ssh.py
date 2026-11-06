import os
import sys
import time
import socket
import threading
import unittest
import paramiko
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.ssh_server import SSHGatewayServer
from threat_intel.logger import HoneypotLogger

class TestEndToEndSSH(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_port = 22225
        cls.server = SSHGatewayServer(host="127.0.0.1", port=cls.test_port)
        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()
        time.sleep(1.0)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.is_running = False
            cls.server.sock.close()
        except Exception:
            pass

    def test_full_ssh_session_workflow(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname="127.0.0.1",
            port=self.test_port,
            username="ubuntu",
            password="123",
            timeout=5.0,
            look_for_keys=False,
            allow_agent=False
        )

        chan = client.invoke_shell()
        chan.settimeout(5.0)

        # 1. Wait for banner & prompt
        buf = ""
        while "$" not in buf:
            buf += chan.recv(1024).decode("utf-8", errors="replace")
        self.assertIn("ubuntu@ubuntu-srv-01", buf)

        # 2. Run whoami
        chan.send("whoami\n")
        time.sleep(0.3)
        buf = chan.recv(2048).decode("utf-8", errors="replace")
        self.assertIn("ubuntu", buf)

        # 3. Test sudo su elevation
        chan.send("sudo su\n")
        time.sleep(0.3)
        buf = chan.recv(2048).decode("utf-8", errors="replace")
        self.assertIn("[sudo] password for ubuntu:", buf)

        # Enter password
        chan.send("123\n")
        time.sleep(0.5)
        buf = ""
        while "#" not in buf:
            buf += chan.recv(2048).decode("utf-8", errors="replace")
        self.assertIn("root@ubuntu-srv-01", buf)

        # 4. Verify elevated root whoami
        chan.send("whoami\n")
        time.sleep(0.3)
        buf = chan.recv(2048).decode("utf-8", errors="replace")
        self.assertIn("root", buf)

        # 5. Root can read /etc/shadow
        chan.send("cat /etc/shadow | grep root\n")
        time.sleep(0.3)
        buf = chan.recv(2048).decode("utf-8", errors="replace")
        self.assertIn("root:", buf)

        # 6. Exit subshell to drop back to ubuntu user
        chan.send("exit\n")
        time.sleep(0.5)
        buf = ""
        while "$" not in buf:
            buf += chan.recv(2048).decode("utf-8", errors="replace")
        self.assertIn("ubuntu@ubuntu-srv-01", buf)

        # Verify we are ubuntu again
        chan.send("whoami\n")
        time.sleep(0.3)
        buf = chan.recv(2048).decode("utf-8", errors="replace")
        self.assertIn("ubuntu", buf)

        # 7. Final exit closes session
        chan.send("exit\n")
        time.sleep(0.5)
        client.close()

if __name__ == "__main__":
    unittest.main()
