import os
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.vfs import VirtualFileSystem
from gateway.state.system_state import LinuxSystemState
from gateway.apt_manager import AptManager
from ai_engine.router import CommandRouter
from ai_engine.llm_client import LLMClient

class TestStatefulLinux(unittest.TestCase):
    def setUp(self):
        self.state = LinuxSystemState(hostname="ubuntu-srv-01")
        self.vfs = VirtualFileSystem(hostname="ubuntu-srv-01", user="ubuntu")
        self.llm = LLMClient()
        self.router = CommandRouter(self.vfs, self.llm)

    def test_basic_shell_commands(self):
        # 1. whoami & id
        out, _, _ = self.router.execute("whoami", user="ubuntu")
        self.assertEqual(out.strip(), "ubuntu")

        out, _, _ = self.router.execute("id", user="ubuntu")
        self.assertIn("uid=1000(ubuntu)", out)
        self.assertIn("gid=1000(ubuntu)", out)
        self.assertIn("27(sudo)", out)

        # 2. pwd & cd
        out, _, _ = self.router.execute("pwd", user="ubuntu")
        self.assertEqual(out.strip(), "/home/ubuntu")

        out, _, _ = self.router.execute("cd /var/log", user="ubuntu")
        self.assertEqual(self.vfs.pwd(), "/var/log")

        out, _, _ = self.router.execute("cd ~", user="ubuntu")
        self.assertEqual(self.vfs.pwd(), "/home/ubuntu")

    def test_file_operations_and_permissions(self):
        # 1. touch & write & cat
        self.router.execute("touch test.txt", user="ubuntu")
        self.router.execute("echo 'Hello Honeypot' > test.txt", user="ubuntu")
        out, _, _ = self.router.execute("cat test.txt", user="ubuntu")
        self.assertEqual(out.strip(), "Hello Honeypot")

        # 2. append
        self.router.execute("echo 'Line 2' >> test.txt", user="ubuntu")
        out, _, _ = self.router.execute("cat test.txt", user="ubuntu")
        self.assertIn("Hello Honeypot", out)
        self.assertIn("Line 2", out)

        # 3. stat & file
        out, _, _ = self.router.execute("stat test.txt", user="ubuntu")
        self.assertIn("File: test.txt", out)
        self.assertIn("Size:", out)

        out, _, _ = self.router.execute("file test.txt", user="ubuntu")
        self.assertIn("ASCII text", out)

        # 4. chmod & chown
        self.router.execute("chmod 600 test.txt", user="ubuntu")
        node = self.vfs._get_node(self.vfs.resolve_path("test.txt"))
        self.assertEqual(node.get("perm"), "600")

        # 5. cp & mv & rm
        self.router.execute("cp test.txt copy.txt", user="ubuntu")
        out, _, _ = self.router.execute("cat copy.txt", user="ubuntu")
        self.assertIn("Hello Honeypot", out)

        self.router.execute("mv copy.txt moved.txt", user="ubuntu")
        out, _, _ = self.router.execute("cat moved.txt", user="ubuntu")
        self.assertIn("Hello Honeypot", out)

        self.router.execute("rm moved.txt", user="ubuntu")
        out, _, _ = self.router.execute("cat moved.txt", user="ubuntu")
        self.assertIn("No such file or directory", out)

        # Cleanup
        self.router.execute("rm test.txt", user="ubuntu")

    def test_pipelines_and_redirection(self):
        # Pipe to grep
        out, _, _ = self.router.execute("cat /etc/passwd | grep ubuntu", user="ubuntu")
        self.assertIn("ubuntu:x:1000:1000", out)

        # Pipe to head & tail
        out, _, _ = self.router.execute("cat /etc/passwd | head -n 3", user="ubuntu")
        self.assertEqual(len(out.strip().splitlines()), 3)

        # Pipe to wc -l
        out, _, _ = self.router.execute("cat /etc/passwd | wc -l", user="ubuntu")
        self.assertTrue(int(out.strip()) >= 5)

        # Chained commands (&&, ;)
        out, _, _ = self.router.execute("echo first && echo second", user="ubuntu")
        self.assertIn("first", out)
        self.assertIn("second", out)

    def test_environment_variables(self):
        self.router.execute("export MY_TEST_VAR=HackerZone", user="ubuntu")
        out, _, _ = self.router.execute("echo $MY_TEST_VAR", user="ubuntu")
        self.assertEqual(out.strip(), "HackerZone")

        out, _, _ = self.router.execute("echo $USER", user="ubuntu")
        self.assertEqual(out.strip(), "ubuntu")

        out, _, _ = self.router.execute("echo $?", user="ubuntu")
        self.assertEqual(out.strip(), "0")

    def test_apt_package_manager(self):
        # 1. apt update as ubuntu (should fail permission)
        out, _, _ = self.router.execute("apt update", user="ubuntu")
        self.assertIn("Permission denied", out)

        # 2. apt update as root (should succeed)
        out, _, _ = self.router.execute("apt update", user="root")
        self.assertIn("Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease", out)
        self.assertIn("Reading package lists... Done", out)

        # 3. apt install htop as root (remove first if previously installed by test)
        self.router.execute("apt remove -y htop", user="root")
        out, _, _ = self.router.execute("apt install -y htop", user="root")
        self.assertIn("Setting up htop", out)

        # Check binary in VFS
        self.assertTrue(self.vfs._get_node("/usr/bin/htop") is not None)

        # Check htop execution
        out, _, _ = self.router.execute("htop", user="ubuntu")
        self.assertIn("Load average:", out)
        self.assertIn("mysqld", out)

        # Check dpkg -l
        out, _, _ = self.router.execute("dpkg -l htop", user="ubuntu")
        self.assertIn("ii  htop", out)

        # Check dpkg -s htop
        out, _, _ = self.router.execute("dpkg -s htop", user="ubuntu")
        self.assertIn("Package: htop", out)
        self.assertIn("Status: install ok installed", out)

    def test_sudo_and_shadow_permission(self):
        # Non-root cannot read /etc/shadow
        ok, res = self.vfs.cat("/etc/shadow", user="ubuntu")
        self.assertFalse(ok)
        self.assertIn("Permission denied", res)

        # Root can read /etc/shadow
        ok, res = self.vfs.cat("/etc/shadow", user="root")
        self.assertTrue(ok)
        self.assertIn("root:", res)
        self.assertIn("ubuntu:", res)

        # sudo cat /etc/shadow
        out, _, _ = self.router.execute("sudo cat /etc/shadow", user="ubuntu")
        self.assertIn("root:", out)
        self.assertIn("ubuntu:", out)

    def test_system_info_commands(self):
        for cmd in ("hostnamectl", "lsb_release", "lscpu", "df -h", "free -h", "ps aux", "systemctl status ssh", "journalctl", "dmesg"):
            out, _, _ = self.router.execute(cmd, user="ubuntu")
            self.assertTrue(len(out) > 0, f"Command {cmd} returned empty output")

if __name__ == "__main__":
    unittest.main()
