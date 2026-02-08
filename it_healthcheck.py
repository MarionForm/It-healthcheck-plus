#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IT HealthCheck PLUS (Windows/Linux/macOS) — Robust edition

✅ System info (OS, hostname, uptime, CPU, RAM)
✅ Disk usage
✅ Network info (IPs, DNS, routing)
✅ Listening ports + process snapshot
✅ Updates / patches (best effort)
✅ Installed software + versions (Windows registry via PowerShell; Linux package managers; macOS partial)
✅ Quick antimalware scan:
   - Windows: Microsoft Defender QuickScan (PowerShell) + fallback MpCmdRun.exe
   - Linux/macOS: ClamAV quick scan if available (clamscan)
✅ Exports:
   - JSON (automation)
   - TXT (human-readable tickets)

Key Improvements:
- FIX UnicodeDecodeError on Windows: subprocess decoding forced with encoding + errors='replace'
- Output truncation to avoid massive files
- Safer command execution (timeouts, rc capture)
"""

import json
import os
import platform
import re
import socket
import subprocess
import sys
from datetime import datetime
from shutil import which as _which


# -----------------------------
# CONFIG
# -----------------------------
MAX_TEXT_CHARS = 12000          # max chars stored for large command outputs
MAX_TEXT_CHARS_SMALL = 6000
MAX_SW_ITEMS_WIN = 2000         # cap installed software items for Windows
MAX_SW_ITEMS_LINUX = 5000       # cap installed software items for Linux
ANTIMALWARE_TIMEOUT_WIN = 900   # seconds
ANTIMALWARE_TIMEOUT_NIX = 900   # seconds


# -----------------------------
# Helpers
# -----------------------------
def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def tool_exists(cmd: str) -> bool:
    return _which(cmd) is not None


def cut_text(s: str, limit: int = MAX_TEXT_CHARS) -> str:
    if not s:
        return s
    if len(s) <= limit:
        return s
    return s[:limit] + "\n...[TRUNCATED]"


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def get_hostname() -> str:
    return socket.gethostname()


def run(cmd, timeout: int = 60):
    """
    Run command and return a dict:
      {
        "rc": int,
        "cmd": cmd,
        "stdout": "...",
        "note": "..."
      }

    Robust decoding:
    - Force encoding='utf-8' + errors='replace' to avoid UnicodeDecodeError on Windows cp1252.
    - shell=True only if cmd is str.
    """
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=isinstance(cmd, str),
            encoding="utf-8",
            errors="replace"
        )
        out = (p.stdout or "") + (p.stderr or "")
        return {"rc": p.returncode, "cmd": cmd, "stdout": out.strip()}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "cmd": cmd, "stdout": "", "note": f"TIMEOUT after {timeout}s"}
    except Exception as e:
        return {"rc": 999, "cmd": cmd, "stdout": "", "note": f"ERROR: {e}"}


def os_info():
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "python": sys.version.split()[0],
    }


# -----------------------------
# Collectors
# -----------------------------
def get_uptime():
    if is_windows():
        r = run("net stats srv", timeout=20)
        m = re.search(r"Statistics since (.+)", r["stdout"], re.IGNORECASE)
        if m:
            return {"boot_time_raw": m.group(1).strip(), "source": "net stats srv"}

        r2 = run("wmic os get lastbootuptime /value", timeout=20)
        m2 = re.search(r"LastBootUpTime=(\d{14})", r2["stdout"])
        return {
            "last_boot_yyyymmddhhmmss": m2.group(1) if m2 else None,
            "source": "wmic os lastbootuptime",
            "raw": cut_text(r2["stdout"], 1500),
            "rc": r2["rc"]
        }

    # Linux/macOS
    if tool_exists("uptime"):
        r = run(["uptime"], timeout=10)
        return {"uptime_raw": r["stdout"], "source": "uptime", "rc": r["rc"]}

    if os.path.exists("/proc/uptime"):
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as f:
                seconds = float(f.read().split()[0])
            return {"uptime_seconds": seconds, "source": "/proc/uptime"}
        except Exception as e:
            return {"error": str(e), "source": "/proc/uptime"}

    return {"info": "uptime not available"}


def get_cpu_ram():
    info = {"cpu": {}, "ram": {}}

    if is_windows():
        r = run("wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors /format:list", timeout=30)
        for line in r["stdout"].splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info["cpu"][k.strip()] = v.strip()
        info["cpu"]["source"] = "wmic cpu"
        info["cpu"]["rc"] = r["rc"]

        r2 = run("wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /format:list", timeout=30)
        mem = {}
        for line in r2["stdout"].splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                mem[k.strip()] = v.strip()
        try:
            total_kb = int(mem.get("TotalVisibleMemorySize", "0"))
            free_kb = int(mem.get("FreePhysicalMemory", "0"))
            info["ram"] = {
                "total_gb": round(total_kb / 1024 / 1024, 2),
                "free_gb": round(free_kb / 1024 / 1024, 2),
                "source": "wmic os memory",
                "rc": r2["rc"]
            }
        except Exception:
            info["ram"] = {"raw": mem, "source": "wmic os memory", "rc": r2["rc"]}

        return info

    # Linux/macOS
    if tool_exists("lscpu"):
        r = run(["lscpu"], timeout=20)
        info["cpu"]["lscpu_raw"] = cut_text(r["stdout"], MAX_TEXT_CHARS_SMALL)
        info["cpu"]["rc"] = r["rc"]
        info["cpu"]["source"] = "lscpu"
    else:
        info["cpu"]["processor"] = platform.processor()
        info["cpu"]["source"] = "platform.processor()"

    if tool_exists("free"):
        r2 = run(["free", "-m"], timeout=10)
        info["ram"]["free_raw"] = r2["stdout"]
        info["ram"]["rc"] = r2["rc"]
        info["ram"]["source"] = "free -m"
    elif tool_exists("vm_stat"):  # macOS
        r2 = run(["vm_stat"], timeout=10)
        info["ram"]["vm_stat_raw"] = cut_text(r2["stdout"], MAX_TEXT_CHARS_SMALL)
        info["ram"]["rc"] = r2["rc"]
        info["ram"]["source"] = "vm_stat"
    else:
        info["ram"]["info"] = "RAM info not available"

    return info


def get_disks():
    if is_windows():
        r = run("wmic logicaldisk get DeviceID,FileSystem,FreeSpace,Size,VolumeName /format:csv", timeout=45)
        return {"wmic_logicaldisk_csv": cut_text(r["stdout"]), "rc": r["rc"], "source": "wmic logicaldisk"}

    if tool_exists("df"):
        r = run(["df", "-h"], timeout=10)
        return {"df_h": r["stdout"], "rc": r["rc"], "source": "df -h"}

    return {"info": "disk info not available"}


def get_network():
    data = {}

    if is_windows():
        r = run("ipconfig /all", timeout=45)
        data["ipconfig_all"] = cut_text(r["stdout"])
        data["ipconfig_rc"] = r["rc"]

        r2 = run("route print", timeout=45)
        data["route_print"] = cut_text(r2["stdout"])
        data["route_rc"] = r2["rc"]

        # Extract DNS servers
        dns_servers = []
        capture = False
        for line in r["stdout"].splitlines():
            if "DNS Servers" in line:
                capture = True
                parts = line.split(":")
                if len(parts) > 1 and parts[1].strip():
                    dns_servers.append(parts[1].strip())
                continue
            if capture:
                if line.startswith("   ") and line.strip():
                    dns_servers.append(line.strip())
                else:
                    capture = False
        data["dns_servers"] = dns_servers

        return data

    # Linux/macOS
    if tool_exists("ip"):
        r = run(["ip", "a"], timeout=10)
        data["ip_a"] = cut_text(r["stdout"])
        data["ip_a_rc"] = r["rc"]

        r2 = run(["ip", "r"], timeout=10)
        data["ip_r"] = cut_text(r2["stdout"], MAX_TEXT_CHARS_SMALL)
        data["ip_r_rc"] = r2["rc"]
    elif tool_exists("ifconfig"):
        r = run(["ifconfig"], timeout=10)
        data["ifconfig"] = cut_text(r["stdout"])
        data["ifconfig_rc"] = r["rc"]

    if tool_exists("nmcli"):
        r3 = run(["nmcli", "dev", "show"], timeout=15)
        data["nmcli_dev_show"] = cut_text(r3["stdout"])
        data["nmcli_rc"] = r3["rc"]

    if os.path.exists("/etc/resolv.conf"):
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
                data["resolv_conf"] = cut_text(f.read().strip(), MAX_TEXT_CHARS_SMALL)
        except Exception as e:
            data["resolv_conf_error"] = str(e)

    return data


def get_listening_ports():
    if is_windows():
        r = run("netstat -ano", timeout=45)
        return {"netstat_ano": cut_text(r["stdout"]), "rc": r["rc"], "source": "netstat -ano"}

    if tool_exists("ss"):
        r = run(["ss", "-tulpn"], timeout=25)
        return {"ss_tulpn": cut_text(r["stdout"]), "rc": r["rc"], "source": "ss -tulpn"}
    if tool_exists("netstat"):
        r = run(["netstat", "-tulpn"], timeout=25)
        return {"netstat_tulpn": cut_text(r["stdout"]), "rc": r["rc"], "source": "netstat -tulpn"}

    return {"info": "No ss/netstat available"}


def get_process_snapshot():
    if is_windows():
        r = run("tasklist /v", timeout=45)
        return {"tasklist_v": cut_text(r["stdout"]), "rc": r["rc"], "source": "tasklist /v"}

    if tool_exists("ps"):
        r = run(["ps", "aux"], timeout=10)
        return {"ps_aux": cut_text(r["stdout"]), "rc": r["rc"], "source": "ps aux"}

    return {"info": "ps not available"}


def get_updates_info():
    if is_windows():
        r = run("wmic qfe get HotFixID,InstalledOn,Description /format:table", timeout=90)
        return {"hotfixes": cut_text(r["stdout"]), "rc": r["rc"], "source": "wmic qfe"}

    # Linux best effort
    if tool_exists("apt"):
        r = run(["bash", "-lc", "apt list --upgradable 2>/dev/null"], timeout=90)
        return {"apt_upgradable": cut_text(r["stdout"]), "rc": r["rc"], "source": "apt list --upgradable"}
    if tool_exists("dnf"):
        r = run(["dnf", "check-update"], timeout=90)
        return {"dnf_check_update": cut_text(r["stdout"]), "rc": r["rc"], "source": "dnf check-update"}
    if tool_exists("yum"):
        r = run(["yum", "check-update"], timeout=90)
        return {"yum_check_update": cut_text(r["stdout"]), "rc": r["rc"], "source": "yum check-update"}
    if tool_exists("pacman"):
        r = run(["bash", "-lc", "pacman -Qu 2>/dev/null"], timeout=90)
        return {"pacman_upgradable": cut_text(r["stdout"]), "rc": r["rc"], "source": "pacman -Qu"}

    return {"info": "updates info not available"}


# -----------------------------
# Installed software + versions
# -----------------------------
def get_installed_software():
    if is_windows():
        # Registry uninstall keys via PowerShell -> JSON
        ps = rf'''
$ErrorActionPreference="SilentlyContinue"
$paths = @(
 "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
 "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
 "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$apps = foreach ($p in $paths) {{
  Get-ItemProperty $p | Where-Object {{ $_.DisplayName -and $_.DisplayName.Trim() -ne "" }} |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}}
$apps |
  Sort-Object DisplayName -Unique |
  Select-Object -First {MAX_SW_ITEMS_WIN} |
  ConvertTo-Json -Depth 3
'''
        r = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=180)

        if r["rc"] == 0 and r["stdout"]:
            try:
                data = json.loads(r["stdout"])
                if isinstance(data, dict):
                    data = [data]
                apps = []
                for a in data:
                    apps.append({
                        "name": a.get("DisplayName"),
                        "version": a.get("DisplayVersion"),
                        "publisher": a.get("Publisher"),
                        "installDate": a.get("InstallDate"),
                        "source": "registry_uninstall_keys"
                    })
                return {"count": len(apps), "apps": apps, "rc": r["rc"], "source": "PowerShell registry"}
            except Exception as e:
                return {"error": f"Failed parsing PowerShell JSON: {e}", "raw": cut_text(r["stdout"], MAX_TEXT_CHARS_SMALL), "rc": r["rc"]}

        return {"error": "Unable to query installed apps via PowerShell", "raw": cut_text(r["stdout"], MAX_TEXT_CHARS_SMALL), "rc": r["rc"]}

    # Linux package list
    if tool_exists("dpkg-query"):
        cmd = f"dpkg-query -W -f='${{Package}}\\t${{Version}}\\n' 2>/dev/null | head -n {MAX_SW_ITEMS_LINUX}"
        r = run(["bash", "-lc", cmd], timeout=90)
        apps = []
        for line in r["stdout"].splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                apps.append({"name": parts[0], "version": parts[1], "source": "dpkg"})
        return {"count": len(apps), "apps": apps, "rc": r["rc"], "source": "dpkg-query"}

    if tool_exists("rpm"):
        cmd = f"rpm -qa --qf '%{{NAME}}\\t%{{VERSION}}-%{{RELEASE}}\\n' 2>/dev/null | head -n {MAX_SW_ITEMS_LINUX}"
        r = run(["bash", "-lc", cmd], timeout=90)
        apps = []
        for line in r["stdout"].splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                apps.append({"name": parts[0], "version": parts[1], "source": "rpm"})
        return {"count": len(apps), "apps": apps, "rc": r["rc"], "source": "rpm -qa"}

    if tool_exists("pacman"):
        cmd = f"pacman -Q 2>/dev/null | head -n {MAX_SW_ITEMS_LINUX}"
        r = run(["bash", "-lc", cmd], timeout=90)
        apps = []
        for line in r["stdout"].splitlines():
            parts = line.split()
            if len(parts) >= 2:
                apps.append({"name": parts[0], "version": parts[1], "source": "pacman"})
        return {"count": len(apps), "apps": apps, "rc": r["rc"], "source": "pacman -Q"}

    # macOS (partial, heavy)
    if platform.system().lower() == "darwin" and tool_exists("system_profiler"):
        r = run(["system_profiler", "SPApplicationsDataType"], timeout=240)
        return {"source": "system_profiler", "raw": cut_text(r["stdout"]), "rc": r["rc"], "note": "Partial output due to truncation."}

    return {"info": "installed software inventory not available on this system"}


# -----------------------------
# Antimalware quick scan
# -----------------------------
def quick_antimalware_scan():
    if is_windows():
        # Try Defender Start-MpScan
        r = run(["powershell", "-NoProfile", "-Command", "Get-Command Start-MpScan"], timeout=20)
        if r["rc"] == 0 and "Start-MpScan" in r["stdout"]:
            ps = "Start-MpScan -ScanType QuickScan; Get-MpComputerStatus | ConvertTo-Json -Depth 3"
            r2 = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=ANTIMALWARE_TIMEOUT_WIN)
            return {
                "engine": "Microsoft Defender",
                "method": "Start-MpScan QuickScan + Get-MpComputerStatus",
                "status": "ok" if r2["rc"] == 0 else f"error_rc_{r2['rc']}",
                "raw": cut_text(r2["stdout"]),
                "rc": r2["rc"],
                "note": r2.get("note")
            }

        # Fallback MpCmdRun.exe
        candidates = [
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe"
        ]
        mpcmd = None
        for c in candidates:
            if os.path.exists(c):
                mpcmd = c
                break

        if not mpcmd:
            # locate newest MpCmdRun in Platform folder
            r3 = run([
                "powershell", "-NoProfile", "-Command",
                r"Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform\' -Recurse -Filter MpCmdRun.exe -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName"
            ], timeout=30)
            path = (r3["stdout"] or "").strip()
            if path and os.path.exists(path):
                mpcmd = path

        if mpcmd:
            cmd = f'"{mpcmd}" -Scan -ScanType 1'
            r4 = run(cmd, timeout=ANTIMALWARE_TIMEOUT_WIN)
            return {
                "engine": "Microsoft Defender",
                "method": "MpCmdRun.exe -Scan -ScanType 1 (Quick)",
                "status": "ok" if r4["rc"] == 0 else f"error_rc_{r4['rc']}",
                "raw": cut_text(r4["stdout"]),
                "rc": r4["rc"],
                "note": r4.get("note")
            }

        return {
            "engine": "unknown",
            "status": "not_available",
            "note": "No Defender CLI found. If you use another AV, integrate its CLI here."
        }

    # Linux/macOS: ClamAV
    if tool_exists("clamscan"):
        home = os.path.expanduser("~")
        targets = [home, "/tmp"]
        cmd = ["clamscan", "-r", "--bell", "--max-filesize=20M", "--max-scansize=200M"] + targets
        r = run(cmd, timeout=ANTIMALWARE_TIMEOUT_NIX)
        # ClamAV return codes: 0=clean, 1=infected found, 2=error
        status = "clean" if r["rc"] == 0 else ("infected_found" if r["rc"] == 1 else f"error_rc_{r['rc']}")
        return {
            "engine": "ClamAV",
            "method": "clamscan recursive quick scan (limited size)",
            "status": status,
            "raw": cut_text(r["stdout"]),
            "rc": r["rc"],
            "note": r.get("note")
        }

    return {"engine": "none", "status": "not_available", "note": "No supported antimalware CLI found (install ClamAV or configure your AV CLI)."}


# -----------------------------
# Report writers
# -----------------------------
def write_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_txt(path: str, report: dict):
    lines = []
    lines.append(f"IT HealthCheck PLUS Report - {report['generated_at']}")
    lines.append("=" * 80)
    lines.append(f"User: {report.get('user')}")
    lines.append(f"Hostname: {report.get('hostname')}")
    lines.append(f"OS: {report.get('os', {}).get('platform')}")
    lines.append("=" * 80)

    def add_section(title: str, content):
        lines.append(f"\n[{title}]")
        if isinstance(content, dict):
            lines.append(json.dumps(content, ensure_ascii=False, indent=2))
        else:
            lines.append(str(content))

    add_section("UPTIME", report.get("uptime"))
    add_section("CPU & RAM", report.get("cpu_ram"))
    add_section("DISKS", report.get("disks"))
    add_section("NETWORK", report.get("network"))
    add_section("LISTENING PORTS", report.get("listening_ports"))
    add_section("PROCESS SNAPSHOT", report.get("process_snapshot"))
    add_section("UPDATES / PATCHES", report.get("updates"))

    # Installed software summary
    lines.append("\n[INSTALLED SOFTWARE (summary)]")
    sw = report.get("installed_software", {})
    if isinstance(sw, dict) and isinstance(sw.get("apps"), list):
        apps = sw["apps"]
        lines.append(f"Count: {sw.get('count', len(apps))} | Source: {sw.get('source')}")
        lines.append("Top 200 entries (name | version | publisher):")
        for a in apps[:200]:
            name = (a.get("name") or "").strip()
            ver = (a.get("version") or "").strip()
            pub = (a.get("publisher") or "").strip()
            lines.append(f"- {name} | {ver} | {pub}")
        if len(apps) > 200:
            lines.append(f"... {len(apps) - 200} more apps (see JSON for full list)")
    else:
        lines.append(json.dumps(sw, ensure_ascii=False, indent=2))

    add_section("ANTIMALWARE QUICK SCAN", report.get("antimalware_quick_scan"))

    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write("\n".join(lines))


# -----------------------------
# Main
# -----------------------------
def main():
    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "user": os.getenv("USERNAME") or os.getenv("USER"),
        "hostname": get_hostname(),
        "os": os_info(),
        "uptime": get_uptime(),
        "cpu_ram": get_cpu_ram(),
        "disks": get_disks(),
        "network": get_network(),
        "listening_ports": get_listening_ports(),
        "process_snapshot": get_process_snapshot(),
        "updates": get_updates_info(),
        "installed_software": get_installed_software(),
        "antimalware_quick_scan": quick_antimalware_scan(),
    }

    base = f"healthcheck_plus_{report['hostname']}_{now_ts()}"
    json_path = base + ".json"
    txt_path = base + ".txt"

    write_json(json_path, report)
    write_txt(txt_path, report)

    print("✅ Report generated:")
    print(f"- {json_path}")
    print(f"- {txt_path}")
    if is_windows():
        print("ℹ️ Tip (Windows): run PowerShell/CMD as Administrator for full antimalware + system queries.")


if __name__ == "__main__":
    main()
