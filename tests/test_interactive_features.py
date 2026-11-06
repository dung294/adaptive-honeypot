import os
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.vfs import VirtualFileSystem
from gateway.state.system_state import LinuxSystemState
from gateway.nano_editor import NanoEditor

class MockChannel:
    """Mock paramiko channel for testing NanoEditor TUI and key handling."""
    def __init__(self, inputs=None):
        self.inputs = inputs or []
        self.output = []

    def send(self, data):
        self.output.append(data)

    def recv(self, n):
        if self.inputs:
            return self.inputs.pop(0)
        return b""

class TestInteractiveFeatures(unittest.TestCase):
    def setUp(self):
        self.state = LinuxSystemState(hostname="ubuntu-srv-01")
        self.vfs = VirtualFileSystem(hostname="ubuntu-srv-01", user="ubuntu")

    def test_sudo_password_verification(self):
        # 1. Correct password for ubuntu
        self.assertTrue(self.state.verify_password("ubuntu", "123"))
        # 2. Wrong password
        self.assertFalse(self.state.verify_password("ubuntu", "wrongpass"))
        # 3. Root password
        self.assertTrue(self.state.verify_password("root", "123"))

    def test_nano_editor_headless(self):
        # Create a test file
        test_file = "/home/ubuntu/nano_test.txt"
        self.vfs.write_file(test_file, "Line 1\nLine 2\nLine 3", user="ubuntu")

        # Simulate NanoEditor:
        # User opens file, moves down, types " Edited", presses Ctrl+O (\x0f), then Ctrl+X (\x18)
        inputs = [
            b"\x1b[B",          # Down arrow
            b" Edited",         # Insert text
            b"\x0f",            # Ctrl+O (Save prompt)
            b"\r",              # Enter to confirm save
            b"\x18"             # Ctrl+X (Exit)
        ]
        mock_chan = MockChannel(inputs)
        editor = NanoEditor(mock_chan, self.vfs, test_file, user="ubuntu")
        editor.run()

        # Verify that changes were saved to VFS
        ok, content = self.vfs.cat(test_file, user="ubuntu")
        self.assertTrue(ok)
        self.assertIn(" Edited", content)
        self.assertIn("Line 1", content)
        self.assertIn("Line 3", content)

        # Cleanup
        self.vfs.rm(test_file, user="ubuntu")

    def test_nano_permission_check(self):
        # /etc/shadow is unwritable for ubuntu
        mock_chan = MockChannel([b"\x18"])  # Ctrl+X
        editor = NanoEditor(mock_chan, self.vfs, "/etc/shadow", user="ubuntu")
        self.assertFalse(editor.is_writable)
        self.assertIn("unwritable", editor.status_message.lower())

if __name__ == "__main__":
    unittest.main()
