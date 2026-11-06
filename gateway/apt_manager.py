import time
import os
from typing import Tuple, Dict, Any, List
from gateway.state.system_state import LinuxSystemState

class AptManager:
    """
    Trình quản lý package Linux giả lập có trạng thái đầy đủ (Stateful APT/DPKG Engine).
    Hỗ trợ:
      - apt update / apt-get update
      - apt upgrade / apt-get upgrade [-y]
      - apt install / apt-get install [-y] <pkg>
      - apt remove / apt purge <pkg>
      - apt autoremove
      - apt list [--installed | --upgradable]
      - apt-cache search <query>
      - dpkg -l [<pattern>]
      - dpkg -s <pkg>
    Đồng bộ dữ liệu trực tiếp vào LinuxSystemState và VirtualFileSystem.
    """

    def __init__(self, state: LinuxSystemState, vfs):
        self.state = state
        self.vfs = vfs

    def handle_apt(self, args: List[str], raw_cmd: str, user: str = "root") -> Tuple[str, int]:
        """
        Xử lý các lệnh gọi apt / apt-get / apt-cache / dpkg.
        Trả về: (stdout_str, returncode)
        """
        if not args:
            return self._apt_usage(), 1

        cmd = args[0]
        subargs = args[1:]

        if cmd in ("apt", "apt-get"):
            return self._handle_apt_cli(subargs, raw_cmd, user)
        elif cmd == "apt-cache":
            return self._handle_apt_cache(subargs, user)
        elif cmd == "dpkg":
            return self._handle_dpkg(subargs, user)
        
        return f"bash: {cmd}: command not found\n", 127

    def _apt_usage(self) -> str:
        return (
            "apt 2.4.11 (amd64)\n"
            "Usage: apt [options] command\n\n"
            "apt is a commandline package manager and provides commands for\n"
            "searching and managing as well as querying information about packages.\n\n"
            "Most used commands:\n"
            "  list - list packages based on package names\n"
            "  search - search in package descriptions\n"
            "  show - show package details\n"
            "  install - install packages\n"
            "  reinstall - reinstall packages\n"
            "  remove - remove packages\n"
            "  autoremove - automatically remove all unused packages\n"
            "  update - update list of available packages\n"
            "  upgrade - upgrade the system by installing/upgrading packages\n"
            "  full-upgrade - upgrade the system by removing/installing/upgrading packages\n"
            "  edit-sources - edit the source information file\n"
            "  satisfy - satisfy dependency strings\n"
        )

    def _handle_apt_cli(self, args: List[str], raw_cmd: str, user: str) -> Tuple[str, int]:
        if not args:
            return self._apt_usage(), 1

        subcmd = args[0]
        flags = [a for a in args[1:] if a.startswith("-")]
        params = [a for a in args[1:] if not a.startswith("-")]

        # 1. apt update
        if subcmd == "update":
            if user != "root":
                err = (
                    "Reading package lists... Done\n"
                    "E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)\n"
                    "E: Unable to lock directory /var/lib/apt/lists/\n"
                    "W: Problem unlinking the file /var/cache/apt/pkgcache.bin - RemoveCaches (13: Permission denied)\n"
                    "W: Problem unlinking the file /var/cache/apt/srcpkgcache.bin - RemoveCaches (13: Permission denied)\n"
                )
                return err, 100

            self.state.last_apt_update = time.strftime("%a, %d %b %Y %H:%M:%S UTC")
            self.state.save()
            out = (
                "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n"
                "Get:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [119 kB]\n"
                "Get:3 http://archive.ubuntu.com/ubuntu jammy-backports InRelease [109 kB]\n"
                "Get:4 http://security.ubuntu.com/ubuntu jammy-security InRelease [110 kB]\n"
                "Get:5 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages [1,720 kB]\n"
                "Get:6 http://archive.ubuntu.com/ubuntu jammy-updates/universe amd64 Packages [1,114 kB]\n"
                "Get:7 http://security.ubuntu.com/ubuntu jammy-security/main amd64 Packages [1,450 kB]\n"
                "Fetched 3,622 kB in 1s (2,840 kB/s)\n"
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "Reading state information... Done\n"
                "All packages are up to date.\n"
            )
            return out, 0

        # 2. apt upgrade
        elif subcmd in ("upgrade", "dist-upgrade", "full-upgrade"):
            if user != "root":
                err = (
                    "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                    "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n"
                )
                return err, 100

            out = (
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "Reading state information... Done\n"
                "Calculating upgrade... Done\n"
                "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
            )
            return out, 0

        # 3. apt install <pkg>
        elif subcmd == "install":
            if user != "root":
                err = (
                    "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                    "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n"
                )
                return err, 100

            if not params:
                return "Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n", 0

            target_pkg = params[0].lower()

            # Đã cài đặt rồi?
            if target_pkg in self.state.packages:
                info = self.state.packages[target_pkg]
                return (
                    f"Reading package lists... Done\n"
                    f"Building dependency tree... Done\n"
                    f"Reading state information... Done\n"
                    f"{target_pkg} is already the newest version ({info.get('version', '1.0.0')}).\n"
                    f"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
                ), 0

            # Kiểm tra trong kho có sẵn
            if target_pkg in self.state.available_packages:
                meta = self.state.available_packages[target_pkg]
                ver = meta.get("version", "1.0.0-1ubuntu1")
                size = meta.get("size", 250)
                desc = meta.get("desc", f"{target_pkg} package")

                # Cài đặt vào state.packages
                self.state.packages[target_pkg] = {
                    "version": ver,
                    "status": "installed",
                    "desc": desc,
                    "installed_size": size * 3
                }

                # Tạo binary giả lập trong VFS
                bin_path = f"/usr/bin/{target_pkg}"
                bin_script = f"#!/bin/bash\n# Simulated binary for {target_pkg}\necho '{target_pkg} {ver}'\n"
                self.vfs.write_file(bin_path, bin_script, user="root")
                self.vfs.chmod(bin_path, "755", user="root")

                # Cập nhật log /var/log/dpkg.log và /var/log/apt/history.log
                now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                dpkg_entry = (
                    f"{now_str} install {target_pkg}:amd64 <none> {ver}\n"
                    f"{now_str} status half-installed {target_pkg}:amd64 {ver}\n"
                    f"{now_str} status unpacked {target_pkg}:amd64 {ver}\n"
                    f"{now_str} status installed {target_pkg}:amd64 {ver}\n"
                )
                self.vfs.write_file("/var/log/dpkg.log", dpkg_entry, append=True, user="root")

                apt_hist = (
                    f"\nStart-Date: {now_str}\n"
                    f"Commandline: {raw_cmd}\n"
                    f"Requested-By: root (0)\n"
                    f"Install: {target_pkg}:amd64 ({ver})\n"
                    f"End-Date: {now_str}\n"
                )
                self.vfs.write_file("/var/log/apt/history.log", apt_hist, append=True, user="root")

                self.state.save()

                out = (
                    f"Reading package lists... Done\n"
                    f"Building dependency tree... Done\n"
                    f"Reading state information... Done\n"
                    f"The following NEW packages will be installed:\n"
                    f"  {target_pkg}\n"
                    f"0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n"
                    f"Need to get {size} kB of archives.\n"
                    f"After this operation, {size * 3} kB of additional disk space will be used.\n"
                    f"Get:1 http://archive.ubuntu.com/ubuntu jammy/main amd64 {target_pkg} amd64 {ver} [{size} kB]\n"
                    f"Fetched {size} kB in 0s (1,250 kB/s)\n"
                    f"Selecting previously unselected package {target_pkg}.\n"
                    f"(Reading database ... 74528 files and directories currently installed.)\n"
                    f"Preparing to unpack .../{target_pkg}_{ver}_amd64.deb ...\n"
                    f"Unpacking {target_pkg} ({ver}) ...\n"
                    f"Setting up {target_pkg} ({ver}) ...\n"
                    f"Processing triggers for man-db (2.10.2-1) ...\n"
                )
                return out, 0
            else:
                # Gói tùy biến không có trong repository chuẩn -> mô phỏng cài đặt generic
                ver = "1.0.0-1"
                self.state.packages[target_pkg] = {
                    "version": ver,
                    "status": "installed",
                    "desc": f"Custom utility {target_pkg}",
                    "installed_size": 512
                }
                bin_path = f"/usr/bin/{target_pkg}"
                self.vfs.write_file(bin_path, f"#!/bin/bash\n# Simulated binary\n", user="root")
                self.vfs.chmod(bin_path, "755", user="root")
                self.state.save()

                out = (
                    f"Reading package lists... Done\n"
                    f"Building dependency tree... Done\n"
                    f"Reading state information... Done\n"
                    f"The following NEW packages will be installed:\n"
                    f"  {target_pkg}\n"
                    f"0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n"
                    f"Need to get 240 kB of archives.\n"
                    f"After this operation, 512 kB of additional disk space will be used.\n"
                    f"Get:1 http://archive.ubuntu.com/ubuntu jammy/universe amd64 {target_pkg} amd64 {ver} [240 kB]\n"
                    f"Fetched 240 kB in 0s (1,150 kB/s)\n"
                    f"Selecting previously unselected package {target_pkg}.\n"
                    f"Unpacking {target_pkg} ({ver}) ...\n"
                    f"Setting up {target_pkg} ({ver}) ...\n"
                )
                return out, 0

        # 4. apt remove / purge <pkg>
        elif subcmd in ("remove", "purge", "autoremove"):
            if user != "root":
                err = (
                    "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                    "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n"
                )
                return err, 100

            if subcmd == "autoremove" or not params:
                return (
                    "Reading package lists... Done\n"
                    "Building dependency tree... Done\n"
                    "Reading state information... Done\n"
                    "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
                ), 0

            target_pkg = params[0].lower()
            if target_pkg not in self.state.packages:
                return (
                    f"Reading package lists... Done\n"
                    f"Building dependency tree... Done\n"
                    f"Reading state information... Done\n"
                    f"Package '{target_pkg}' is not installed, so not removed\n"
                    f"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
                ), 0

            ver = self.state.packages[target_pkg].get("version", "1.0.0")
            del self.state.packages[target_pkg]

            # Xóa binary khỏi VFS nếu có
            self.vfs.rm(f"/usr/bin/{target_pkg}", user="root")
            self.vfs.rm(f"/usr/sbin/{target_pkg}", user="root")

            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            dpkg_entry = (
                f"{now_str} remove {target_pkg}:amd64 {ver} <none>\n"
                f"{now_str} status half-configured {target_pkg}:amd64 {ver}\n"
                f"{now_str} status half-installed {target_pkg}:amd64 {ver}\n"
                f"{now_str} status config-files {target_pkg}:amd64 {ver}\n"
                f"{now_str} status not-installed {target_pkg}:amd64 <none>\n"
            )
            self.vfs.write_file("/var/log/dpkg.log", dpkg_entry, append=True, user="root")
            self.state.save()

            out = (
                f"Reading package lists... Done\n"
                f"Building dependency tree... Done\n"
                f"Reading state information... Done\n"
                f"The following packages will be REMOVED:\n"
                f"  {target_pkg}\n"
                f"0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\n"
                f"After this operation, 1,024 kB disk space will be freed.\n"
                f"(Reading database ... 74520 files and directories currently installed.)\n"
                f"Removing {target_pkg} ({ver}) ...\n"
                f"Processing triggers for man-db (2.10.2-1) ...\n"
            )
            return out, 0

        # 5. apt list
        elif subcmd == "list":
            lines = ["Listing... Done"]
            installed_only = "--installed" in flags or "-i" in flags
            upgradable_only = "--upgradable" in flags or "-u" in flags

            if upgradable_only:
                return "Listing... Done\n", 0

            for name, meta in sorted(self.state.packages.items()):
                ver = meta.get("version", "1.0.0")
                lines.append(f"{name}/jammy,now {ver} amd64 [installed]")

            if not installed_only:
                for name, meta in sorted(self.state.available_packages.items()):
                    if name not in self.state.packages:
                        ver = meta.get("version", "1.0.0")
                        lines.append(f"{name}/jammy {ver} amd64")

            return "\n".join(lines) + "\n", 0

        # 6. apt search
        elif subcmd == "search":
            query = params[0].lower() if params else ""
            lines = ["Sorting... Done", "Full Text Search... Done"]
            all_pkgs = {**self.state.packages, **self.state.available_packages}
            for name, meta in sorted(all_pkgs.items()):
                desc = meta.get("desc", "")
                if query in name or query in desc.lower():
                    status = "[installed]" if name in self.state.packages else ""
                    lines.append(f"{name}/jammy {meta.get('version', '1.0.0')} amd64 {status}\n  {desc}\n")
            return "\n".join(lines), 0

        return self._apt_usage(), 1

    def _handle_apt_cache(self, args: List[str], user: str) -> Tuple[str, int]:
        if not args:
            return "apt-cache 2.4.11 (amd64)\nUsage: apt-cache [options] command\n", 1
        subcmd = args[0]
        params = args[1:]
        if subcmd == "search":
            query = params[0].lower() if params else ""
            lines = []
            all_pkgs = {**self.state.packages, **self.state.available_packages}
            for name, meta in sorted(all_pkgs.items()):
                desc = meta.get("desc", "")
                if query in name or query in desc.lower():
                    lines.append(f"{name} - {desc}")
            return ("\n".join(lines) + "\n") if lines else "", 0
        return "", 0

    def _handle_dpkg(self, args: List[str], user: str) -> Tuple[str, int]:
        if not args:
            return "dpkg: error: need an action option\nType dpkg --help for help about installing and deinstalling packages [*];\n", 2

        subcmd = args[0]
        params = args[1:]

        # dpkg -l [<pattern>]
        if subcmd in ("-l", "--list"):
            header = (
                "Desired=Unknown/Install/Remove/Purge/Hold\n"
                "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
                "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
                "||/ Name           Version               Architecture Description\n"
                "+++-==============-=====================-============-================================================================="
            )
            lines = [header]
            pat = params[0].lower() if params else ""
            for name, meta in sorted(self.state.packages.items()):
                if pat and (pat not in name):
                    continue
                ver = meta.get("version", "1.0.0")[:21].ljust(21)
                desc = meta.get("desc", "")[:60]
                lines.append(f"ii  {name.ljust(14)} {ver} amd64        {desc}")
            return "\n".join(lines) + "\n", 0

        # dpkg -s <pkg>
        elif subcmd in ("-s", "--status"):
            if not params:
                return "dpkg-query: error: --status takes at least one package name argument\n", 1
            pkg = params[0].lower()
            if pkg in self.state.packages:
                meta = self.state.packages[pkg]
                out = (
                    f"Package: {pkg}\n"
                    f"Status: install ok installed\n"
                    f"Priority: optional\n"
                    f"Section: utils\n"
                    f"Installed-Size: {meta.get('installed_size', 1024)}\n"
                    f"Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n"
                    f"Architecture: amd64\n"
                    f"Version: {meta.get('version', '1.0.0')}\n"
                    f"Description: {meta.get('desc', 'Standard Linux package')}\n"
                )
                return out, 0
            else:
                return f"dpkg-query: package '{pkg}' is not installed and no information is available\n", 1

        return "", 0
