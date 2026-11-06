import time
import os
from typing import Tuple, Dict, Any, List, Optional
from gateway.state.system_state import LinuxSystemState

class AptManager:
    """
    Trình quản lý package Linux giả lập có trạng thái đầy đủ (Stateful APT/DPKG Engine).
    Hỗ trợ mô phỏng độ trễ đường truyền tải mạng (Realistic Network Pacing):
    - Tải từng gói, từng mirror repo với độ trễ 0.2s - 0.4s như máy chủ Ubuntu thật.
    - Cập nhật trực tiếp vào LinuxSystemState và VirtualFileSystem.
    """

    def __init__(self, state: LinuxSystemState, vfs):
        self.state = state
        self.vfs = vfs

    def handle_apt(self, args: List[str], raw_cmd: str, user: str = "root", channel = None) -> Tuple[str, int]:
        """
        Xử lý các lệnh gọi apt / apt-get / apt-cache / dpkg.
        Nếu channel != None, phát luồng (stream) từng dòng với độ trễ mạng thực tế.
        Trả về: (stdout_str, returncode)
        """
        if not args:
            return self._apt_usage(), 1

        cmd = args[0]
        subargs = args[1:]

        if cmd in ("apt", "apt-get"):
            return self._handle_apt_cli(subargs, raw_cmd, user, channel=channel)
        elif cmd == "apt-cache":
            return self._handle_apt_cache(subargs, user)
        elif cmd == "dpkg":
            return self._handle_dpkg(subargs, user)
        
        return f"bash: {cmd}: command not found\n", 127

    def _stream_output(self, lines: List[Tuple[str, float]], channel = None) -> str:
        """Phát luồng kết quả ra channel với độ trễ mô phỏng tốc độ mạng của user"""
        full_lines = []
        for text, delay in lines:
            full_lines.append(text)
            if channel:
                try:
                    for subline in text.split("\n"):
                        channel.send(subline + "\r\n")
                    if delay > 0:
                        time.sleep(delay)
                except Exception:
                    pass
        output = "\n".join(full_lines) + "\n"
        if channel:
            return "__STREAMED__" + output
        return output

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

    def _handle_apt_cli(self, args: List[str], raw_cmd: str, user: str, channel = None) -> Tuple[str, int]:
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
            
            # Mô phỏng quá trình tải repo qua mạng với độ trễ từng dòng chân thực
            pacing_lines = [
                ("Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease", 0.35),
                ("Get:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [119 kB]", 0.30),
                ("Get:3 http://archive.ubuntu.com/ubuntu jammy-backports InRelease [109 kB]", 0.25),
                ("Get:4 http://security.ubuntu.com/ubuntu jammy-security InRelease [110 kB]", 0.30),
                ("Get:5 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages [1,720 kB]", 0.45),
                ("Get:6 http://archive.ubuntu.com/ubuntu jammy-updates/universe amd64 Packages [1,114 kB]", 0.40),
                ("Get:7 http://security.ubuntu.com/ubuntu jammy-security/main amd64 Packages [1,450 kB]", 0.35),
                ("Fetched 3,622 kB in 2s (1,680 kB/s)", 0.25),
                ("Reading package lists... Done", 0.30),
                ("Building dependency tree... Done", 0.20),
                ("Reading state information... Done", 0.20),
                ("All packages are up to date.", 0.10)
            ]
            out = self._stream_output(pacing_lines, channel=channel)
            return out, 0

        # 2. apt upgrade
        elif subcmd in ("upgrade", "dist-upgrade", "full-upgrade"):
            if user != "root":
                err = (
                    "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                    "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n"
                )
                return err, 100

            pacing_lines = [
                ("Reading package lists... Done", 0.30),
                ("Building dependency tree... Done", 0.20),
                ("Reading state information... Done", 0.20),
                ("Calculating upgrade... Done", 0.35),
                ("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.", 0.10)
            ]
            out = self._stream_output(pacing_lines, channel=channel)
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
                pacing_lines = [
                    ("Reading package lists... Done", 0.25),
                    ("Building dependency tree... Done", 0.20),
                    ("Reading state information... Done", 0.20),
                    (f"{target_pkg} is already the newest version ({info.get('version', '1.0.0')}).", 0.15),
                    ("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.", 0.10)
                ]
                out = self._stream_output(pacing_lines, channel=channel)
                return out, 0

            # Gói có trong danh mục kho
            if target_pkg in self.state.available_packages:
                meta = self.state.available_packages[target_pkg]
                ver = meta.get("version", "1.0.0-1ubuntu1")
                size = meta.get("size", 250)
                desc = meta.get("desc", f"{target_pkg} package")
            else:
                ver = "1.0.0-1"
                size = 320
                desc = f"Custom utility {target_pkg}"

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

            pacing_lines = [
                ("Reading package lists... Done", 0.30),
                ("Building dependency tree... Done", 0.20),
                ("Reading state information... Done", 0.20),
                (f"The following NEW packages will be installed:\n  {target_pkg}", 0.25),
                ("0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.", 0.15),
                (f"Need to get {size} kB of archives.", 0.15),
                (f"After this operation, {size * 3} kB of additional disk space will be used.", 0.25),
                (f"Get:1 http://archive.ubuntu.com/ubuntu jammy/main amd64 {target_pkg} amd64 {ver} [{size} kB]", 0.50),
                (f"Fetched {size} kB in 1s (420 kB/s)", 0.25),
                (f"Selecting previously unselected package {target_pkg}.", 0.20),
                ("(Reading database ... 74528 files and directories currently installed.)", 0.25),
                (f"Preparing to unpack .../{target_pkg}_{ver}_amd64.deb ...", 0.30),
                (f"Unpacking {target_pkg} ({ver}) ...", 0.35),
                (f"Setting up {target_pkg} ({ver}) ...", 0.40),
                ("Processing triggers for man-db (2.10.2-1) ...", 0.30)
            ]
            out = self._stream_output(pacing_lines, channel=channel)
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
                pacing_lines = [
                    ("Reading package lists... Done", 0.25),
                    ("Building dependency tree... Done", 0.20),
                    ("Reading state information... Done", 0.20),
                    ("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.", 0.10)
                ]
                return self._stream_output(pacing_lines, channel=channel), 0

            target_pkg = params[0].lower()
            if target_pkg not in self.state.packages:
                pacing_lines = [
                    ("Reading package lists... Done", 0.25),
                    ("Building dependency tree... Done", 0.20),
                    ("Reading state information... Done", 0.20),
                    (f"Package '{target_pkg}' is not installed, so not removed", 0.15),
                    ("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.", 0.10)
                ]
                return self._stream_output(pacing_lines, channel=channel), 0

            ver = self.state.packages[target_pkg].get("version", "1.0.0")
            del self.state.packages[target_pkg]

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

            pacing_lines = [
                ("Reading package lists... Done", 0.25),
                ("Building dependency tree... Done", 0.20),
                ("Reading state information... Done", 0.20),
                (f"The following packages will be REMOVED:\n  {target_pkg}", 0.20),
                ("0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.", 0.15),
                ("After this operation, 1,024 kB disk space will be freed.", 0.20),
                ("(Reading database ... 74520 files and directories currently installed.)", 0.25),
                (f"Removing {target_pkg} ({ver}) ...", 0.35),
                ("Processing triggers for man-db (2.10.2-1) ...", 0.25)
            ]
            return self._stream_output(pacing_lines, channel=channel), 0

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
