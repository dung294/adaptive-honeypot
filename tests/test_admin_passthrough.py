import unittest
import uuid
import paramiko
from pathlib import Path
from gateway.ssh_server import HoneypotSSHInterface
from threat_intel.logger import HoneypotLogger
import config

class TestAdminPassthrough(unittest.TestCase):
    def setUp(self):
        self.logger = HoneypotLogger()
        self.interface = HoneypotSSHInterface(
            client_ip="192.168.1.100",
            client_port=54321,
            logger=self.logger
        )

    def test_admin_password_auth_success(self):
        """Admin đăng nhập bằng mật khẩu đặc quyền -> is_admin = True"""
        res = self.interface.check_auth_password("nhuthang", "ThangAdminSecret2026!")
        self.assertEqual(res, paramiko.AUTH_SUCCESSFUL)
        self.assertTrue(self.interface.is_admin)

    def test_hacker_password_auth_routes_to_honeypot(self):
        """Hacker đoán trúng mật khẩu bẫy -> is_admin = False (vào Sandbox)"""
        res = self.interface.check_auth_password("ubuntu", "123")
        self.assertEqual(res, paramiko.AUTH_SUCCESSFUL)
        self.assertFalse(self.interface.is_admin)

    def test_hacker_wrong_password_auth_failed(self):
        """Hacker nhập sai mật khẩu -> từ chối"""
        res = self.interface.check_auth_password("ubuntu", "wrongpass999_xyz")
        self.assertEqual(res, paramiko.AUTH_FAILED)
        self.assertFalse(self.interface.is_admin)

    def test_admin_public_key_auth(self):
        """Admin đăng nhập bằng SSH Public Key đã đăng ký -> is_admin = True"""
        # Tạo test key
        test_key = paramiko.RSAKey.generate(1024)
        key_line = f"ssh-rsa {test_key.get_base64()} admin@test\n"
        
        # Ghi tạm vào admin_authorized_keys
        auth_file = config.ADMIN_AUTHORIZED_KEYS_FILE
        orig_content = auth_file.read_text(encoding="utf-8") if auth_file.exists() else ""
        try:
            with open(auth_file, "a", encoding="utf-8") as f:
                f.write("\n" + key_line)

            # Test với key hợp lệ
            res = self.interface.check_auth_publickey("nhuthang", test_key)
            self.assertEqual(res, paramiko.AUTH_SUCCESSFUL)
            self.assertTrue(self.interface.is_admin)

            # Test với key lạ không đăng ký
            foreign_key = paramiko.RSAKey.generate(1024)
            interface2 = HoneypotSSHInterface("10.0.0.5", 43210, self.logger)
            res2 = interface2.check_auth_publickey("root", foreign_key)
            self.assertEqual(res2, paramiko.AUTH_FAILED)
            self.assertFalse(interface2.is_admin)

        finally:
            with open(auth_file, "w", encoding="utf-8") as f:
                f.write(orig_content)

if __name__ == "__main__":
    unittest.main()
