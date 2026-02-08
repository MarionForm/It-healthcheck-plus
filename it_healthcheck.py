#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IT HealthCheck & Inventory PLUS (Windows/Linux/macOS)
- System info (OS, hostname, uptime, CPU, RAM)
- Disk usage
- Network info (IPs, gateway, DNS)
- Listening ports + processes
- Updates / patches (best effort)
- Installed software + versions (Windows registry via PowerShell; Linux package managers)
- Quick antimalware scan:
    - Windows: Microsoft Defender QuickScan (PowerShell or MpCmdRun)
    - Linux/macOS: ClamAV quick scan if available (clamscan)
- Saves report to TXT + JSON
"""

import json
import os
import platform
import re
import socket
import subprocess
import sys
from datetime import datetime

# ------------------------
# Helpers
# ------------------------

def run(cmd, timeout=60):
    """Run command and return (rc, stdout). cmd can be str (shell) or list."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=isinstance(cmd, str)
        )
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out.strip()
    except Exception as e:
        return 999, f"ERROR running {cmd}: {e}"

def which(cmd):
    from shutil import which as _which
    return _which(cmd) is not None

def now_ts():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def get_hostname():
    return socket.gethostname()

def get_os():
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "python": sys.version.split()[0],
    }

def is_windows():
    return platform.system().lower().startswith("win")

def section_cut(s, limit=12000):
    if not s:
        return s
    return s[:limit] + ("\n...[TRUNCATED]" if len(s) > limit else "")

# ------------------------
# Data collectors
# ------------------------

def get_uptime():
    if is_windows():
        rc, out = run("net stats srv", timeout=20)
        m = re.search(r"Statistics since (.+)", out, re.IGNORECASE)
        if m:
            return {"boot_time_raw": m.group(1).strip()}

        rc, out = run("wmic os get lastbootuptime /value", timeout=20)
        m = re.search(r"LastBootUpTime=(\d{14})", out)
        return {"last_boot_yyyymmddhhmmss": m.group(1) if m else None, "raw": section_cut(out, 1500)}

    # Linux/macOS
    if which("uptime"):
        rc, out = run(["uptime"], timeout=10)
        return {"uptime_raw": out}

    if os.path.exists("/proc/uptime"):
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as f:
                seconds = float(f.read().split()[0])
            return {"uptime_seconds": seconds}
        except Exception as e:
            return {"error": str(e)}

    return {"info": "uptime not available"}

def get_cpu_ram():
    info = {"cpu": {}, "ram": {}}

    if is_windows():
        rc, out = run("wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors /format:list", timeout=20)
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info["cpu"][k.strip()] = v.strip()

        rc, out = run("wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /format:list", timeout=20)
        mem = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                mem[k.strip()] = v.strip()
        try:
            total_kb = int(mem.get("TotalVisibleMemorySize", "0"))
            free_kb = int(mem.get("FreePhysicalMemory", "0"))
            info["ram"] = {
                "total_gb": round(total_kb / 1024 / 1024, 2),
                "free_gb": round(free_kb / 1024 / 1024, 2),
            }
        except Exception:
            info["ram"]["raw"] = mem

    else:
        if which("lscpu"):
            rc, out = run(["lscpu"], timeout=20)
            info["cpu"]["lscpu_raw"] = section_cut(out, 6000)
        else:
            info["cpu"]["processor"] = platform.processor()

        if which("free"):
            rc, out = run(["free", "-m"], timeout=10)
            info["ram"]["free_raw"] = out
        elif which("vm_stat"):  # macOS
            rc, out = run(["vm_stat"], timeout=10)
            info["ram"]["vm_stat_raw"] = out
        else:
            info["ram"]["info"] = "RAM info not available"

    return info

def get_disks():
    if is_windows():
        rc, out = run("wmic logicaldisk get DeviceID,FileSystem,FreeSpace,Size,VolumeName /format:csv", timeout=30)
        return {"wmic_logicaldisk_csv": out}
    if which("df"):
        rc, out = run(["df", "-h"], timeout=10)
        return {"df_h": out}
    return {"info": "disk info not available"}

def get_network():
    data = {}

    if is_windows():
        rc, ipconfig = run("ipconfig /all", timeout=30)
        data["ipconfig_all"] = section_cut(ipconfig, 12000)

        rc, route = run("route print", timeout=30)
        data["route_print"] = section_cut(route, 12000)

        dns_servers = []
        capture = False
        for line in ipconfig.splitlines():
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
    if which("ip"):
        rc, out = run(["ip", "a"], timeout=10)
        data["ip_a"] = section_cut(out, 12000)
        rc, out = run(["ip", "r"], timeout=10)
        data["ip_r"] = section_cut(out, 8000)
    elif which("ifconfig"):
        rc, out = run(["ifconfig"], timeout=10)
        data["ifconfig"] = section_cut(out, 12000)

    if which("nmcli"):
        rc, out = run(["nmcli", "dev", "show"], timeout=15)
        data["nmcli_dev_show"] = section_cut(out, 12000)

    if os.path.exists("/etc/resolv.conf"):
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                data["resolv_conf"] = section_cut(f.read().strip(), 6000)
        except Exception as e:
            data["resolv_conf_error"] = str(e)

    return data

def get_listening_ports():
    if is_windows():
        rc, out = run("netstat -ano", timeout=30)
        return {"netstat_ano": section_cut(out, 12000)}

    if which("ss"):
        rc, out = run(["ss", "-tulpn"], timeout=20)
        return {"ss_tulpn": section_cut(out, 12000)}
    if which("netstat"):
        rc, out = run(["netstat", "-tulpn"], timeout=20)
        return {"netstat_tulpn": section_cut(out, 12000)}
    return {"info": "No ss/netstat available"}

def get_process_snapshot():
    if is_windows():
        rc, out = run("tasklist /v", timeout=30)
        return {"tasklist_v": section_cut(out, 12000)}
    if which("ps"):
        rc, out = run(["ps", "aux"], timeout=10)
        return {"ps_aux": section_cut(out, 12000)}
    return {"info": "ps not available"}

def get_updates_info():
    if is_windows():
        rc, out = run("wmic qfe get HotFixID,InstalledOn,Description /format:table", timeout=60)
        return {"hotfixes": section_cut(out, 12000)}

    # Linux best effort
    if which("apt"):
        rc, out = run(["bash", "-lc", "apt list --upgradable 2>/dev/null"], timeout=60)
        return {"apt_upgradable": section_cut(out, 12000)}
    if which("dnf"):
        rc, out = run(["dnf", "check-update"], timeout=60)
        return {"dnf_check_update": section_cut(out, 12000)}
    if which("yum"):
        rc, out = run(["yum", "check-update"], timeout=60)
        return {"yum_check_update": section_cut(out, 12000)}
    if which("pacman"):
        rc, out = run(["bash", "-lc", "pacman -Qu 2>/dev/null"], timeout=60)
        return {"pacman_upgradable": section_cut(out, 12000)}
    return {"info": "updates info not available"}

# ------------------------
# Installed software (NEW)
# ------------------------

def get_installed_software():
    """
    Returns a dict:
      - Windows: list of {name, version, publisher, installDate, source}
      - Linux: list of packages (best effort with dpkg/rpm/pacman)
      - macOS: list via system_profiler SPApplicationsDataType (can be slow)
    """
    if is_windows():
        # PowerShell to read uninstall registry keys (both 64/32 + HKCU)
        ps = r'''
$ErrorActionPreference="SilentlyContinue"
$paths = @(
 "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
 "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
 "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$apps = foreach ($p in $paths) {
  Get-ItemProperty $p | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}
$apps |
  Sort-Object DisplayName -Unique |
  Select-Object -First 2000 |
  ConvertTo-Json -Depth 3
'''
        rc, out = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=120)
        if rc == 0 and out:
            try:
                data = json.loads(out)
                # Normalize to list
                if isinstance(data, dict):
                    data = [data]
                normalized = []
                for a in data:
                    normalized.append({
                        "name": a.get("DisplayName"),
                        "version": a.get("DisplayVersion"),
                        "publisher": a.get("Publisher"),
                        "installDate": a.get("InstallDate"),
                        "source": "registry_uninstall_keys",
                    })
                return {"count": len(normalized), "apps": normalized}
            except Exception as e:
                return {"error": f"Failed parsing PowerShell JSON: {e}", "raw": section_cut(out, 6000)}
        return {"error": "Unable to query installed apps via PowerShell", "raw": section_cut(out, 6000)}

    # Linux
    if which("dpkg-query"):
        # name + version
        cmd = r"dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | head -n 5000"
        rc, out = run(["bash", "-lc", cmd], timeout=60)
        apps = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                apps.append({"name": parts[0], "version": parts[1], "source": "dpkg"})
        return {"count": len(apps), "apps": apps}

    if which("rpm"):
        cmd = r"rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | head -n 5000"
        rc, out = run(["bash", "-lc", cmd], timeout=60)
        apps = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                apps.append({"name": parts[0], "version": parts[1], "source": "rpm"})
        return {"count": len(apps), "apps": apps}

    if which("pacman"):
        cmd = r"pacman -Q 2>/dev/null | head -n 5000"
        rc, out = run(["bash", "-lc", cmd], timeout=60)
        apps = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                apps.append({"name": parts[0], "version": parts[1], "source": "pacman"})
        return {"count": len(apps), "apps": apps}

    # macOS best-effort (can be heavy)
    if platform.system().lower() == "darwin" and which("system_profiler"):
        rc, out = run(["system_profiler", "SPApplicationsDataType"], timeout=180)
        return {"source": "system_profiler", "raw": section_cut(out, 12000), "note": "For full list, increase cut limit in code."}

    return {"info": "installed software inventory not available on this system"}

# ------------------------
# Antimalware quick scan (NEW)
# ------------------------

def quick_antimalware_scan():
    """
    Windows:
      - Try Defender via PowerShell Start-MpScan -ScanType QuickScan
      - Fallback MpCmdRun.exe -Scan -ScanType 1
    Linux/macOS:
      - If clamscan exists -> quick scan on common dirs (HOME + /tmp), limited output
      - Otherwise report not available
    """
    if is_windows():
        result = {"engine": None, "method": None, "status": None, "raw": None}

        # Check Defender availability
        rc, out = run(["powershell", "-NoProfile", "-Command", "Get-Command Start-MpScan"], timeout=20)
        if rc == 0 and "Start-MpScan" in out:
            # Launch quick scan (may require admin; can take time)
            ps = "Start-MpScan -ScanType QuickScan; Get-MpComputerStatus | ConvertTo-Json -Depth 3"
            rc2, out2 = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=600)
            result["engine"] = "Microsoft Defender"
            result["method"] = "PowerShell Start-MpScan QuickScan + Get-MpComputerStatus"
            result["status"] = "ok" if rc2 == 0 else f"error_rc_{rc2}"
            result["raw"] = section_cut(out2, 12000)
            return result

        # Fallback MpCmdRun
        candidates = [
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe",  # sometimes exists
        ]
        mpcmd = None
        for c in candidates:
            if os.path.exists(c):
                mpcmd = c
                break

        if not mpcmd:
            # Try locating in Platform dir
            rc3, out3 = run(["powershell", "-NoProfile", "-Command",
                             r"Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform\' -Recurse -Filter MpCmdRun.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName"], timeout=30)
            path = out3.strip()
            if path and os.path.exists(path):
                mpcmd = path

        if mpcmd:
            cmd = f'"{mpcmd}" -Scan -ScanType 1'
            rc4, out4 = run(cmd, timeout=600)
            result["engine"] = "Microsoft Defender"
            result["method"] = "MpCmdRun.exe -Scan -ScanType 1 (Quick)"
            result["status"] = "ok" if rc4 == 0 else f"error_rc_{rc4}"
            result["raw"] = section_cut(out4, 12000)
            return result

        return {
            "engine": "unknown",
            "status": "not_available",
            "note": "Microsoft Defender commands not found. If you use another AV, integrate its CLI here."
        }

    # Linux/macOS - ClamAV
    if which("clamscan"):
        home = os.path.expanduser("~")
        targets = [home, "/tmp"]
        # Keep it light: scan only specific size? clamscan has --max-filesize/--max-scansize
        cmd = ["clamscan", "-r", "--bell", "--max-filesize=20M", "--max-scansize=200M"] + targets
        rc, out = run(cmd, timeout=900)
        return {
            "engine": "ClamAV",
            "method": "clamscan recursive quick scan (limited size)",
            "status": "ok" if rc in (0, 1) else f"error_rc_{rc}",  # 1 can mean infected found
            "raw": section_cut(out, 12000),
            "note": "rc=1 may indicate malware found; check the output."
        }

    return {
        "engine": "none",
        "status": "not_available",
        "note": "No supported antimalware CLI found (install ClamAV or configure your AV CLI)."
    }

# ------------------------
# Main
# ------------------------

def main():
    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "user": os.getenv("USERNAME") or os.getenv("USER"),
        "hostname": get_hostname(),
        "os": get_os(),
        "uptime": get_uptime(),
        "cpu_ram": get_cpu_ram(),
        "disks": get_disks(),
        "network": get_network(),
        "listening_ports": get_listening_ports(),
        "process_snapshot": get_process_snapshot(),
        "updates": get_updates_info(),
        "installed_software": get_installed_software(),         # NEW
        "antimalware_quick_scan": quick_antimalware_scan(),     # NEW
    }

    base = f"healthcheck_plus_{get_hostname()}_{now_ts()}"
    json_path = base + ".json"
    txt_path = base + ".txt"

    # JSON output
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # TXT output (human-readable)
    lines = []
    lines.append(f"IT HealthCheck PLUS Report - {report['generated_at']}")
    lines.append("=" * 78)
    lines.append(f"User: {report['user']}")
    lines.append(f"Hostname: {report['hostname']}")
    lines.append(f"OS: {report['os']['platform']}")
    lines.append("=" * 78)

    def add_section(title, content):
        lines.append(f"\n[{title}]")
        if isinstance(content, dict):
            lines.append(json.dumps(content, ensure_ascii=False, indent=2))
        else:
            lines.append(str(content))

    add_section("UPTIME", report["uptime"])
    add_section("CPU & RAM", report["cpu_ram"])
    add_section("DISKS", report["disks"])
    add_section("NETWORK", report["network"])
    add_section("LISTENING PORTS", report["listening_ports"])
    add_section("PROCESS SNAPSHOT", report["process_snapshot"])
    add_section("UPDATES / PATCHES", report["updates"])

    # Installed software: keep TXT compact
    lines.append("\n[INSTALLED SOFTWARE (summary)]")
    sw = report.get("installed_software", {})
    if isinstance(sw, dict) and "apps" in sw and isinstance(sw["apps"], list):
        lines.append(f"Count: {sw.get('count', len(sw['apps']))}")
        lines.append("Top 200 entries (name | version | publisher):")
        for a in sw["apps"][:200]:
            name = (a.get("name") or "").strip()
            ver = (a.get("version") or "").strip()
            pub = (a.get("publisher") or "").strip()
            lines.append(f"- {name} | {ver} | {pub}")
        if len(sw["apps"]) > 200:
            lines.append(f"... {len(sw['apps']) - 200} more apps (see JSON for full list)")
    else:
        lines.append(json.dumps(sw, ensure_ascii=False, indent=2))

    add_section("ANTIMALWARE QUICK SCAN", report["antimalware_quick_scan"])

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"✅ Report generated:\n- {json_path}\n- {txt_path}")
    print("ℹ️ If antimalware scan requires admin rights, run terminal as Administrator/root.")

if __name__ == "__main__":
    main()
