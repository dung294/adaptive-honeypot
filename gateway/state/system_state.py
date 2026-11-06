import os
import json
import time
import copy
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

STATE_DIR = Path(__file__).resolve().parent
PERSISTENCE_FILE = STATE_DIR / "system_state.json"

class LinuxSystemState:
    """
    Singleton quản lý trạng thái máy chủ Linux ảo xuyên suốt (Persistent Shared State).
    Lưu trữ filesystem, users, passwords, packages, system logs, services.
    Được đồng bộ xuống đĩa (persistence) để giữ nguyên trạng thái qua nhiều phiên SSH kết nối lại.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(LinuxSystemState, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, hostname: str = "ubuntu-srv-01"):
        if self._initialized:
            return
        self._initialized = True
        self.hostname = hostname
        self.state_file = PERSISTENCE_FILE
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        
        self.users = {
            "root": {"uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash", "password": "123"},
            "ubuntu": {"uid": 1000, "gid": 1000, "home": "/home/ubuntu", "shell": "/bin/bash", "password": "123"},
            "daemon": {"uid": 1, "gid": 1, "home": "/usr/sbin", "shell": "/usr/sbin/nologin", "password": "*"},
            "bin": {"uid": 2, "gid": 2, "home": "/bin", "shell": "/usr/sbin/nologin", "password": "*"},
            "sys": {"uid": 3, "gid": 3, "home": "/dev", "shell": "/usr/sbin/nologin", "password": "*"},
            "sync": {"uid": 4, "gid": 65534, "home": "/bin", "shell": "/bin/sync", "password": "*"},
            "www-data": {"uid": 33, "gid": 33, "home": "/var/www", "shell": "/usr/sbin/nologin", "password": "*"},
            "backup": {"uid": 34, "gid": 34, "home": "/var/backups", "shell": "/usr/sbin/nologin", "password": "*"},
            "sshd": {"uid": 103, "gid": 65534, "home": "/run/sshd", "shell": "/usr/sbin/nologin", "password": "*"},
            "mysql": {"uid": 104, "gid": 110, "home": "/nonexistent", "shell": "/bin/false", "password": "*"}
        }

        self.groups = {
            "root": {"gid": 0, "members": ["root"]},
            "daemon": {"gid": 1, "members": ["daemon"]},
            "bin": {"gid": 2, "members": ["bin"]},
            "sys": {"gid": 3, "members": ["sys"]},
            "adm": {"gid": 4, "members": ["ubuntu", "syslog"]},
            "sudo": {"gid": 27, "members": ["ubuntu"]},
            "www-data": {"gid": 33, "members": ["www-data"]},
            "shadow": {"gid": 42, "members": []},
            "mysql": {"gid": 110, "members": ["mysql"]},
            "docker": {"gid": 999, "members": ["ubuntu"]},
            "ubuntu": {"gid": 1000, "members": ["ubuntu"]}
        }

        self.services = {
            "ssh": {"name": "ssh", "desc": "OpenBSD Secure Shell server", "active": "active", "sub": "running", "pid": 640},
            "sshd": {"name": "sshd", "desc": "OpenBSD Secure Shell server", "active": "active", "sub": "running", "pid": 640},
            "cron": {"name": "cron", "desc": "Regular background program processing daemon", "active": "active", "sub": "running", "pid": 520},
            "rsyslog": {"name": "rsyslog", "desc": "System Logging Service", "active": "active", "sub": "running", "pid": 410},
            "systemd-resolved": {"name": "systemd-resolved", "desc": "Network Name Resolution", "active": "active", "sub": "running", "pid": 350},
            "systemd-journald": {"name": "systemd-journald", "desc": "Journal Service", "active": "active", "sub": "running", "pid": 80},
            "nginx": {"name": "nginx", "desc": "A high performance web server and a reverse proxy server", "active": "active", "sub": "running", "pid": 820},
            "mysql": {"name": "mysql", "desc": "MySQL Community Server", "active": "active", "sub": "running", "pid": 750}
        }

        self.packages = {
            "coreutils": {"version": "8.32-4.1ubuntu1.2", "status": "installed", "desc": "GNU core utilities", "installed_size": 17850},
            "bash": {"version": "5.1-6ubuntu1.1", "status": "installed", "desc": "GNU Bourne Again SHell", "installed_size": 6500},
            "openssh-server": {"version": "1:8.9p1-3ubuntu0.6", "status": "installed", "desc": "secure shell (SSH) server", "installed_size": 1420},
            "openssh-client": {"version": "1:8.9p1-3ubuntu0.6", "status": "installed", "desc": "secure shell (SSH) client", "installed_size": 4100},
            "nano": {"version": "6.2-1", "status": "installed", "desc": "small, friendly text editor inspired by Pico", "installed_size": 840},
            "curl": {"version": "7.81.0-1ubuntu1.15", "status": "installed", "desc": "command line tool for transferring data with URL syntax", "installed_size": 450},
            "wget": {"version": "1.21.2-2ubuntu1.1", "status": "installed", "desc": "retrieves files from the web", "installed_size": 980},
            "tar": {"version": "1.34+dfsg-1ubuntu0.1.22.04.1", "status": "installed", "desc": "GNU version of the tar archiving utility", "installed_size": 820},
            "gzip": {"version": "1.10-4ubuntu4.1", "status": "installed", "desc": "GNU compression utilities", "installed_size": 240},
            "net-tools": {"version": "1.60+git20181103.0eebece-1ubuntu5", "status": "installed", "desc": "NET-3 networking toolkit", "installed_size": 850},
            "iproute2": {"version": "5.15.0-1ubuntu2", "status": "installed", "desc": "networking and traffic control tools", "installed_size": 3200},
            "systemd": {"version": "249.11-0ubuntu3.12", "status": "installed", "desc": "system and service manager", "installed_size": 14200},
            "sudo": {"version": "1.9.9-1ubuntu2.4", "status": "installed", "desc": "Provide limited super user privileges to specific users", "installed_size": 2100},
            "apt": {"version": "2.4.11", "status": "installed", "desc": "commandline package manager", "installed_size": 4300},
            "dpkg": {"version": "1.21.1ubuntu2.2", "status": "installed", "desc": "Debian package management system", "installed_size": 7100},
            "python3": {"version": "3.10.12-1~22.04.3", "status": "installed", "desc": "interactive high-level object-oriented language (default python3 version)", "installed_size": 65},
            "nginx": {"version": "1.18.0-6ubuntu14.4", "status": "installed", "desc": "small, powerful, scalable web/proxy server", "installed_size": 2700},
            "mysql-server": {"version": "8.0.36-0ubuntu0.22.04.1", "status": "installed", "desc": "MySQL database server binaries and system database setup", "installed_size": 29000}
        }

        # Kho lưu trữ có sẵn để cài thêm
        self.available_packages = {
            "vim": {"version": "2:8.2.3995-1ubuntu2.16", "desc": "Vi IMproved - enhanced vi editor", "size": 3200, "deps": ["vim-runtime"]},
            "htop": {"version": "3.0.5-7build2", "desc": "interactive processes viewer", "size": 185, "deps": []},
            "git": {"version": "1:2.34.1-1ubuntu1.10", "desc": "fast, scalable, distributed revision control system", "size": 3200, "deps": ["git-man"]},
            "nmap": {"version": "7.91+dfsg1-1ubuntu1", "desc": "The Network Mapper", "size": 5400, "deps": []},
            "netcat": {"version": "1.10-46", "desc": "TCP/IP swiss army knife -- transitional package", "size": 20, "deps": ["netcat-openbsd"]},
            "socat": {"version": "1.7.4.1-3ubuntu4", "desc": "multipurpose relay for bidirectional data transfer", "size": 380, "deps": []},
            "tmux": {"version": "3.2a-4ubuntu0.4", "desc": "terminal multiplexer", "size": 490, "deps": []},
            "tree": {"version": "2.0.2-1", "desc": "displays an indented directory tree, in color", "size": 52, "deps": []},
            "docker.io": {"version": "24.0.7-0ubuntu2~22.04.1", "desc": "Linux container runtime", "size": 45000, "deps": ["containerd"]},
            "tcpdump": {"version": "4.99.1-3ubuntu0.2", "desc": "command-line network traffic analyzer", "size": 520, "deps": []}
        }

        self.upgradable_packages = {
            "openssh-server": "1:8.9p1-3ubuntu0.10",
            "curl": "7.81.0-1ubuntu1.16",
            "sudo": "1.9.9-1ubuntu2.5",
            "systemd": "249.11-0ubuntu3.13"
        }

        self.apt_updated_time = None
        self.custom_processes: List[Dict[str, Any]] = []
        self.crontabs: Dict[str, str] = {
            "root": "*/15 * * * * /root/deploy.sh > /dev/null 2>&1\n"
        }
        self.next_pid: int = 1500
        self.fs = self._init_default_filesystem()
        
        # Nạp lại dữ liệu đã lưu nếu có
        self.load_state()

    def _init_default_filesystem(self) -> Dict[str, Any]:
        """Tạo cây thư mục phân cấp chuẩn Linux Ubuntu 22.04 LTS với đầy đủ metadata."""
        now_str = "Oct 30 12:00"
        return {
            "/": {
                "type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str,
                "children": {
                    "bin": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                    "sbin": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                    "boot": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                    "dev": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                    "lib": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                    "media": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                    "mnt": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                    "opt": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                    "srv": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                    "sys": {"type": "dir", "owner": "root", "group": "root", "perm": "555", "mtime": now_str, "children": {}},
                    "run": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                    "tmp": {"type": "dir", "owner": "root", "group": "root", "perm": "777", "mtime": now_str, "children": {}},
                    "etc": {
                        "type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str,
                        "children": {
                            "hostname": {"type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str, "content": f"{self.hostname}\n"},
                            "issue": {"type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str, "content": "Ubuntu 22.04.4 LTS \\n \\l\n"},
                            "os-release": {
                                "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                "content": (
                                    'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
                                    'NAME="Ubuntu"\n'
                                    'VERSION_ID="22.04"\n'
                                    'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
                                    'VERSION_CODENAME=jammy\n'
                                    'ID=ubuntu\n'
                                    'ID_LIKE=debian\n'
                                    'HOME_URL="https://www.ubuntu.com/"\n'
                                    'SUPPORT_URL="https://help.ubuntu.com/"\n'
                                    'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
                                )
                            },
                            "hosts": {
                                "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                "content": (
                                    "127.0.0.1 localhost\n"
                                    f"127.0.1.1 {self.hostname}\n\n"
                                    "::1 ip6-localhost ip6-loopback\n"
                                    "fe00::0 ip6-localnet\n"
                                    "ff02::1 ip6-allnodes\n"
                                    "ff02::2 ip6-allrouters\n"
                                    "192.168.101.50 db-cluster.internal\n"
                                    "192.168.101.80 gitlab.internal\n"
                                )
                            },
                            "fstab": {
                                "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                "content": (
                                    "# /etc/fstab: static file system information.\n"
                                    "/dev/sda1 / ext4 errors=remount-ro 0 1\n"
                                    "/dev/sda2 none swap sw 0 0\n"
                                )
                            },
                            "resolv.conf": {
                                "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                "content": (
                                    "# Generated by systemd-resolved\n"
                                    "nameserver 127.0.0.53\n"
                                    "options edns0 trust-ad\n"
                                    "search localdomain\n"
                                )
                            },
                            "crontab": {
                                "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                "content": (
                                    "SHELL=/bin/sh\n"
                                    "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
                                    "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
                                    "25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
                                    "*/15 * * * * root /root/deploy.sh > /dev/null 2>&1\n"
                                )
                            },
                            "sudoers": {
                                "type": "file", "owner": "root", "group": "root", "perm": "440", "mtime": now_str,
                                "content": (
                                    "Defaults\tenv_reset\n"
                                    "Defaults\tmail_badpass\n"
                                    "Defaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n\n"
                                    "# User privilege specification\n"
                                    "root\tALL=(ALL:ALL) ALL\n\n"
                                    "# Members of the admin group may gain root privileges\n"
                                    "%admin ALL=(ALL) ALL\n\n"
                                    "# Allow members of group sudo to execute any command\n"
                                    "%sudo\tALL=(ALL:ALL) ALL\n"
                                )
                            },
                            "passwd": {"type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str, "content": ""},
                            "shadow": {"type": "file", "owner": "root", "group": "shadow", "perm": "640", "mtime": now_str, "content": ""},
                            "group": {"type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str, "content": ""},
                            "ssh": {
                                "type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str,
                                "children": {
                                    "sshd_config": {
                                        "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                        "content": (
                                            "Port 22\n"
                                            "PermitRootLogin prohibit-password\n"
                                            "PasswordAuthentication yes\n"
                                            "X11Forwarding no\n"
                                            "Subsystem sftp /usr/lib/openssh/sftp-server\n"
                                        )
                                    }
                                }
                            },
                            "apt": {
                                "type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str,
                                "children": {
                                    "sources.list": {
                                        "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                        "content": (
                                            "deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse\n"
                                            "deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse\n"
                                            "deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse\n"
                                        )
                                    }
                                }
                            }
                        }
                    },
                    "home": {
                        "type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str,
                        "children": {
                            "ubuntu": {
                                "type": "dir", "owner": "ubuntu", "group": "ubuntu", "perm": "755", "mtime": now_str,
                                "children": {
                                    ".bashrc": {"type": "file", "owner": "ubuntu", "group": "ubuntu", "perm": "644", "mtime": now_str, "content": "# ~/.bashrc\nexport PATH=$PATH:/usr/local/bin\n"},
                                    ".profile": {"type": "file", "owner": "ubuntu", "group": "ubuntu", "perm": "644", "mtime": now_str, "content": "# ~/.profile\nif [ -n \"$BASH_VERSION\" ]; then\n  [ -f \"$HOME/.bashrc\" ] && . \"$HOME/.bashrc\"\nfi\n"},
                                    ".bash_history": {"type": "file", "owner": "ubuntu", "group": "ubuntu", "perm": "600", "mtime": now_str, "content": "sudo apt update\nsudo systemctl status nginx\nls -la\ncat notes.txt\n"},
                                    "notes.txt": {
                                        "type": "file", "owner": "ubuntu", "group": "ubuntu", "perm": "644", "mtime": now_str,
                                        "content": (
                                            "Deployment Notes:\n"
                                            "1. Database host: 192.168.101.50\n"
                                            "2. App backup script in /tmp\n"
                                            "3. Sudo password is configured for ubuntu user\n"
                                        )
                                    }
                                }
                            }
                        }
                    },
                    "root": {
                        "type": "dir", "owner": "root", "group": "root", "perm": "700", "mtime": now_str,
                        "children": {
                            ".bashrc": {"type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str, "content": "# ~/.bashrc for root\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"},
                            ".profile": {"type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str, "content": "# ~/.profile for root\n"},
                            ".bash_history": {"type": "file", "owner": "root", "group": "root", "perm": "600", "mtime": now_str, "content": "apt update && apt upgrade -y\nsudo systemctl restart sshd\ncat /var/log/syslog\n"},
                            "notes.txt": {
                                "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                "content": (
                                    "CONFIDENTIAL INFRASTRUCTURE CREDENTIALS:\n"
                                    "DB Master: 192.168.101.50\n"
                                    "User: root_cluster\n"
                                    "Pass: EnterpriseP@ss2026!\n"
                                )
                            },
                            "deploy.sh": {
                                "type": "file", "owner": "root", "group": "root", "perm": "755", "mtime": now_str,
                                "content": "#!/bin/bash\necho 'Starting server deployment...'\nsystemctl restart nginx\nsystemctl restart mysql\n"
                            }
                        }
                    },
                    "proc": {
                        "type": "dir", "owner": "root", "group": "root", "perm": "555", "mtime": now_str,
                        "children": {
                            "cpuinfo": {
                                "type": "file", "owner": "root", "group": "root", "perm": "444", "mtime": now_str,
                                "content": (
                                    "processor\t: 0\n"
                                    "vendor_id\t: GenuineIntel\n"
                                    "model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
                                    "cpu MHz\t\t: 2399.998\n"
                                    "cache size\t: 30720 KB\n"
                                    "cpu cores\t: 2\n\n"
                                    "processor\t: 1\n"
                                    "vendor_id\t: GenuineIntel\n"
                                    "model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
                                    "cpu MHz\t\t: 2399.998\n"
                                    "cache size\t: 30720 KB\n"
                                    "cpu cores\t: 2\n"
                                )
                            },
                            "meminfo": {
                                "type": "file", "owner": "root", "group": "root", "perm": "444", "mtime": now_str,
                                "content": (
                                    "MemTotal:        4016140 kB\n"
                                    "MemFree:         2140512 kB\n"
                                    "MemAvailable:    2856230 kB\n"
                                    "Buffers:          142100 kB\n"
                                    "Cached:           912400 kB\n"
                                    "SwapTotal:       2097148 kB\n"
                                    "SwapFree:        2097148 kB\n"
                                )
                            },
                            "version": {
                                "type": "file", "owner": "root", "group": "root", "perm": "444", "mtime": now_str,
                                "content": "Linux version 5.15.0-88-generic (buildd@lcy02-amd64-001) (gcc version 11.4.0) #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023\n"
                            }
                        }
                    },
                    "var": {
                        "type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str,
                        "children": {
                            "log": {
                                "type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str,
                                "children": {
                                    "syslog": {
                                        "type": "file", "owner": "syslog", "group": "adm", "perm": "640", "mtime": now_str,
                                        "content": (
                                            "Oct 30 12:00:01 ubuntu-srv-01 CRON[1042]: (root) CMD (/root/deploy.sh > /dev/null 2>&1)\n"
                                            "Oct 30 12:05:14 ubuntu-srv-01 sshd[1200]: Accepted password for root from 192.168.1.1 port 54210 ssh2\n"
                                            "Oct 30 12:05:14 ubuntu-srv-01 systemd-logind[420]: New session 3 of user root.\n"
                                        )
                                    },
                                    "auth.log": {
                                        "type": "file", "owner": "syslog", "group": "adm", "perm": "640", "mtime": now_str,
                                        "content": (
                                            "Oct 30 12:05:14 ubuntu-srv-01 sshd[1200]: Accepted password for ubuntu from 192.168.1.1 port 54210 ssh2\n"
                                            "Oct 30 12:05:14 ubuntu-srv-01 systemd-logind[420]: New session 3 of user ubuntu.\n"
                                        )
                                    },
                                    "dpkg.log": {
                                        "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                        "content": (
                                            "2023-10-30 11:58:10 startup archives unpack\n"
                                            "2023-10-30 11:58:12 status installed nginx:all 1.18.0-6ubuntu14.4\n"
                                        )
                                    },
                                    "apt": {
                                        "type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str,
                                        "children": {
                                            "history.log": {
                                                "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                                "content": (
                                                    "Start-Date: 2023-10-30  11:58:00\n"
                                                    "Commandline: apt install nginx -y\n"
                                                    "Install: nginx:amd64 (1.18.0-6ubuntu14.4)\n"
                                                    "End-Date: 2023-10-30  11:58:15\n"
                                                )
                                            },
                                            "term.log": {
                                                "type": "file", "owner": "root", "group": "root", "perm": "644", "mtime": now_str,
                                                "content": "Log started: 2023-10-30 11:58:00\nUnpacking nginx (1.18.0-6ubuntu14.4) ...\nSetting up nginx (1.18.0-6ubuntu14.4) ...\n"
                                            }
                                        }
                                    }
                                }
                            },
                            "www": {
                                "type": "dir", "owner": "www-data", "group": "www-data", "perm": "755", "mtime": now_str,
                                "children": {
                                    "html": {
                                        "type": "dir", "owner": "www-data", "group": "www-data", "perm": "755", "mtime": now_str,
                                        "children": {
                                            "index.html": {"type": "file", "owner": "www-data", "group": "www-data", "perm": "644", "mtime": now_str, "content": "<h1>Welcome to Enterprise Web Portal</h1>\n"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "usr": {
                        "type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str,
                        "children": {
                            "bin": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                            "sbin": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                            "lib": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}},
                            "share": {"type": "dir", "owner": "root", "group": "root", "perm": "755", "mtime": now_str, "children": {}}
                        }
                    }
                }
            }
        }

    def verify_password(self, username: str, password: str) -> bool:
        """Xác thực mật khẩu người dùng Linux ảo."""
        if username not in self.users:
            return False
        expected = self.users[username].get("password")
        if not expected or expected == "*":
            return False
        return expected == password

    def sync_user_files(self):
        """Đồng bộ /etc/passwd, /etc/shadow, /etc/group từ self.users và self.groups."""
        passwd_lines = []
        shadow_lines = []
        for u, info in self.users.items():
            passwd_lines.append(f"{u}:x:{info['uid']}:{info['gid']}:{u.capitalize()}:{info['home']}:{info['shell']}")
            pwd_hash = info.get("password_hash")
            if not pwd_hash:
                raw_p = info.get("password", "*")
                if raw_p == "*":
                    pwd_hash = "*"
                else:
                    pwd_hash = f"$6$salt${hashlib.sha256(raw_p.encode()).hexdigest()[:24]}"
            shadow_lines.append(f"{u}:{pwd_hash}:19600:0:99999:7:::")

        group_lines = []
        for g, info in self.groups.items():
            members_str = ",".join(info.get("members", []))
            group_lines.append(f"{g}:x:{info['gid']}:{members_str}")

        etc = self.fs["/"]["children"]["etc"]["children"]
        etc["passwd"]["content"] = "\n".join(passwd_lines) + "\n"
        etc["shadow"]["content"] = "\n".join(shadow_lines) + "\n"
        etc["group"]["content"] = "\n".join(group_lines) + "\n"

    def append_log(self, log_path: str, message: str):
        """Ghi nối dòng nhật ký vào file ảo tương ứng (auth.log, syslog, dpkg.log)."""
        node = self.get_node(log_path)
        if node and node.get("type") == "file":
            timestamp = time.strftime("%b %d %H:%M:%S")
            log_line = f"{timestamp} {self.hostname} {message}\n"
            node["content"] = node.get("content", "") + log_line

    def add_process(self, user: str, cmd: str, cpu: str = "0.0", mem: str = "0.1") -> int:
        """Đăng ký tiến trình ngầm (background process) do attacker khởi tạo."""
        pid = self.next_pid
        self.next_pid += 1
        now_hm = time.strftime("%H:%M")
        proc = {
            "pid": pid,
            "user": user,
            "cpu": cpu,
            "mem": mem,
            "vsz": 18500 + (pid * 3),
            "rss": 4200 + (pid * 2),
            "tty": "?",
            "stat": "Sl",
            "start": now_hm,
            "time": "0:00",
            "cmd": cmd
        }
        self.custom_processes.append(proc)
        self.save_state()
        return pid

    def kill_process(self, pid_or_name: str) -> bool:
        """Loại bỏ tiến trình ảo khi bị kill."""
        target_idx = -1
        for idx, p in enumerate(self.custom_processes):
            if str(p.get("pid")) == str(pid_or_name) or str(pid_or_name) in p.get("cmd", ""):
                target_idx = idx
                break
        if target_idx >= 0:
            self.custom_processes.pop(target_idx)
            self.save_state()
            return True
        return False

    def save_state(self):
        """Lưu toàn bộ trạng thái hệ sinh thái ảo ra tệp json."""
        try:
            self.sync_user_files()
            data = {
                "hostname": self.hostname,
                "users": self.users,
                "groups": self.groups,
                "services": self.services,
                "packages": self.packages,
                "apt_updated_time": self.apt_updated_time,
                "custom_processes": self.custom_processes,
                "crontabs": self.crontabs,
                "next_pid": self.next_pid,
                "fs": self.fs
            }
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def save(self):
        """Alias cho save_state."""
        self.save_state()

    def load_state(self):
        """Khôi phục trạng thái từ tệp json nếu đã tồn tại."""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.hostname = data.get("hostname", self.hostname)
                    self.users = data.get("users", self.users)
                    self.groups = data.get("groups", self.groups)
                    self.services = data.get("services", self.services)
                    self.packages = data.get("packages", self.packages)
                    self.apt_updated_time = data.get("apt_updated_time", None)
                    self.custom_processes = data.get("custom_processes", self.custom_processes)
                    self.crontabs = data.get("crontabs", self.crontabs)
                    self.next_pid = data.get("next_pid", self.next_pid)
                    if "fs" in data:
                        self.fs = data["fs"]
            except Exception:
                pass
        self.sync_user_files()

    def get_node(self, norm_path: str) -> Optional[Dict[str, Any]]:
        if norm_path == "/":
            return self.fs["/"]
        current = self.fs["/"]
        for seg in norm_path.strip("/").split("/"):
            if not seg:
                continue
            if current.get("type") != "dir" or seg not in current.get("children", {}):
                return None
            current = current["children"][seg]
        return current
