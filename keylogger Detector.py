import os
import psutil
import socket
import time
import json
import hashlib
import platform
import subprocess
from datetime import datetime
from collections import defaultdict

#THREAT INTELLIGENCE CONFIG

# Expanded process keywords with severity weights
PROCESS_THREATS = {
    "critical": ["keylogger", "ratclient", "njrat", "darkcomet", "blackshades"],
    "high":     ["logger", "spy", "monitor", "sniff", "capture", "hook", "inject"],
    "medium":   ["vnc", "remote", "rdp", "screen", "record", "dump"],
    "low":      ["scan", "crawler", "scraper"],
}

# File patterns (name, extension) with context
FILE_THREATS = {
    "critical": [".keylog", "keystrokes", "passwords.txt", "credentials"],
    "high":     ["keylog", "keystroke", "spy", "screenshot", "screen_cap"],
    "medium":   ["record", "capture", ".log", "activity_log"],
    "low":      ["monitor", "tracker"],
}

# Benign processes to whitelist (reduce false positives)
PROCESS_WHITELIST = {
    "system", "svchost.exe", "explorer.exe", "taskmgr.exe",
    "python", "python3", "code", "vscode", "chrome", "firefox",
    "msedge", "teams", "slack", "discord", "zoom", "outlook",
}

# Trusted network ranges (your local network)
TRUSTED_IPS = {"127.0.0.1", "::1", "0.0.0.0"}

# Known malicious or suspicious ports
SUSPICIOUS_PORTS = {
    1337, 4444, 5555, 6666, 7777, 8888,  # common RAT ports
    1080, 3128, 8080,                      # proxy ports (context matters)
    23, 69, 445, 135,                      # legacy/dangerous protocols
}

# Known safe ports (reduce noise)
COMMON_SAFE_PORTS = {
    80, 443, 53, 22, 25, 587, 993, 995,
    3000, 3306, 5432, 8000, 8443, 8888,
}


#  SEVERITY SCORING ENGINE

SEVERITY_SCORES = {"critical": 10, "high": 7, "medium": 4, "low": 1}

def score_to_severity(score: int) -> str:
    if score >= 10: return "critical"
    if score >= 7:  return "high"
    if score >= 4:  return "medium"
    if score >= 1:  return "low"
    return "safe"


#  PROCESS SCANNER (Enhanced)

def scan_processes() -> list[dict]:
    """
    Scans running processes with:
    - Severity scoring
    - Whitelist filtering
    - Path verification (packed/temp executables are suspicious)
    - Parent process awareness
    """
    flagged = []

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "create_time"]):
        try:
            info = proc.info
            pname = (info.get("name") or "").lower()
            exe   = (info.get("exe") or "").lower()
            cmd   = " ".join(info.get("cmdline") or []).lower()

            # Skip whitelisted processes
            if pname in PROCESS_WHITELIST:
                continue

            score = 0
            reasons = []

            # Check name against threat keywords
            for severity, keywords in PROCESS_THREATS.items():
                for kw in keywords:
                    if kw in pname or kw in cmd:
                        score += SEVERITY_SCORES[severity]
                        reasons.append(f"Keyword '{kw}' in process name/command ({severity})")

            # Running from temp/unusual location is suspicious
            suspicious_paths = ["/tmp/", "/var/tmp/", "\\temp\\", "\\appdata\\local\\temp\\", "%temp%"]
            for path in suspicious_paths:
                if path in exe:
                    score += SEVERITY_SCORES["high"]
                    reasons.append(f"Executable running from suspicious path: {exe}")

            # No executable path (process hiding technique)
            if info.get("exe") is None and pname not in {"system", "idle", "[kworker]"}:
                score += SEVERITY_SCORES["medium"]
                reasons.append("Process has no visible executable path (possible evasion)")

            if score > 0:
                flagged.append({
                    "pid":      info["pid"],
                    "name":     info.get("name", "unknown"),
                    "exe":      info.get("exe", "N/A"),
                    "user":     info.get("username", "N/A"),
                    "started":  datetime.fromtimestamp(info.get("create_time", 0)).strftime("%H:%M:%S"),
                    "score":    score,
                    "severity": score_to_severity(score),
                    "reasons":  reasons,
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Sort by risk score descending
    return sorted(flagged, key=lambda x: x["score"], reverse=True)


#  FILE SCANNER (Enhanced)

def file_entropy(filepath: str) -> float:
    """Calculate Shannon entropy of a file (high entropy = possibly encrypted/packed)."""
    try:
        with open(filepath, "rb") as f:
            data = f.read(8192)  # read first 8KB
        if not data:
            return 0.0
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
        length = len(data)
        import math
        entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
        return round(entropy, 2)
    except Exception:
        return 0.0


def scan_files() -> list[dict]:
    """
    Scans files with:
    - Smarter keyword matching (avoid false positives like 'keyboard')
    - Entropy analysis for encrypted payloads
    - Executable detection in non-standard locations
    """
    flagged = []
    search_dirs = ["/tmp", os.path.expanduser("~"), "/var/tmp"]

    # Deduplicated false-positive terms
    FALSE_POSITIVE_TERMS = {"keyboard", "bookmarks", "bookmarks_bar", "logon", "dialog"}

    for directory in search_dirs:
        try:
            for root, dirs, files in os.walk(directory):
                # Skip known safe dirs to speed up scan
                dirs[:] = [d for d in dirs if d not in {
                    ".git", "node_modules", "__pycache__", ".cache",
                    "Library", "Application Support"
                }]

                for fname in files:
                    fpath = os.path.join(root, fname)
                    flower = fname.lower()

                    score = 0
                    reasons = []

                    # Skip false positives
                    if any(fp in flower for fp in FALSE_POSITIVE_TERMS):
                        continue

                    # Check filename against threat patterns
                    for severity, patterns in FILE_THREATS.items():
                        for pattern in patterns:
                            if pattern in flower:
                                score += SEVERITY_SCORES[severity]
                                reasons.append(f"Filename matches threat pattern '{pattern}' ({severity})")

                    # Hidden file (starts with dot) in home dir
                    if fname.startswith(".") and root == os.path.expanduser("~"):
                        score += SEVERITY_SCORES["low"]
                        reasons.append("Hidden file in home directory")

                    # Executable in /tmp is almost always suspicious
                    if root in ("/tmp", "/var/tmp") and os.access(fpath, os.X_OK):
                        score += SEVERITY_SCORES["high"]
                        reasons.append("Executable file in /tmp")

                    if score > 0:
                        try:
                            stat = os.stat(fpath)
                            size = stat.st_size
                            modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                        except OSError:
                            size, modified = 0, "N/A"

                        entropy = file_entropy(fpath) if score >= SEVERITY_SCORES["medium"] else None

                        # High entropy + suspicious name = critical
                        if entropy and entropy > 7.5:
                            score += SEVERITY_SCORES["high"]
                            reasons.append(f"High file entropy ({entropy}) — possibly encrypted/packed")

                        flagged.append({
                            "path":     fpath,
                            "size_kb":  round(size / 1024, 1),
                            "modified": modified,
                            "entropy":  entropy,
                            "score":    score,
                            "severity": score_to_severity(score),
                            "reasons":  reasons,
                        })

        except PermissionError:
            continue

    return sorted(flagged, key=lambda x: x["score"], reverse=True)


#  NETWORK SCANNER

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def scan_network() -> list[dict]:
    """
    Scans network connections with:
    - Port-based risk scoring
    - Hostname resolution
    - Filtering out trusted/common connections
    - Connection count per process (lots of connections = suspicious)
    """
    flagged = []
    conn_count = defaultdict(int)

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("[!] Network scan requires elevated privileges for full results")
        return []

    # Count connections per PID first
    for conn in connections:
        if conn.pid:
            conn_count[conn.pid] += 1

    for conn in connections:
        if not conn.raddr:
            continue

        remote_ip   = conn.raddr.ip
        remote_port = conn.raddr.port
        local_port  = conn.laddr.port if conn.laddr else 0

        # Skip trusted local connections
        if remote_ip in TRUSTED_IPS:
            continue

        score = 0
        reasons = []

        # Known suspicious remote port
        if remote_port in SUSPICIOUS_PORTS:
            score += SEVERITY_SCORES["high"]
            reasons.append(f"Connecting to known suspicious port {remote_port}")

        # Process has abnormally many connections
        if conn.pid and conn_count[conn.pid] > 20:
            score += SEVERITY_SCORES["medium"]
            reasons.append(f"Process has {conn_count[conn.pid]} simultaneous connections")

        # Unusual local ports (ephemeral ranges are normal, but low ports from user processes aren't)
        if 1 < local_port < 1024:
            score += SEVERITY_SCORES["low"]
            reasons.append(f"Connection from privileged local port {local_port}")

        # Non-HTTPS/HTTP encrypted traffic on unusual ports
        if remote_port not in COMMON_SAFE_PORTS and conn.status == "ESTABLISHED":
            score += SEVERITY_SCORES["low"]
            reasons.append(f"Active connection to non-standard port {remote_port}")

        # Resolve hostname for context
        hostname = resolve_hostname(remote_ip) if score > 0 else remote_ip

        if score > 0:
            # Get process name if possible
            try:
                proc_name = psutil.Process(conn.pid).name() if conn.pid else "unknown"
            except Exception:
                proc_name = "unknown"

            flagged.append({
                "local":    f"{conn.laddr.ip}:{local_port}" if conn.laddr else "N/A",
                "remote":   f"{remote_ip}:{remote_port}",
                "hostname": hostname,
                "status":   conn.status,
                "pid":      conn.pid,
                "process":  proc_name,
                "score":    score,
                "severity": score_to_severity(score),
                "reasons":  reasons,
            })

    return sorted(flagged, key=lambda x: x["score"], reverse=True)


#  SYSTEM INFO

def get_system_info() -> dict:
    return {
        "hostname":   socket.gethostname(),
        "os":         platform.system(),
        "os_version": platform.version(),
        "platform":   platform.platform(),
        "cpu_count":  psutil.cpu_count(),
        "ram_gb":     round(psutil.virtual_memory().total / (1024**3), 1),
        "uptime_hrs": round((time.time() - psutil.boot_time()) / 3600, 1),
    }


#  REPORT GENERATION

def generate_report(processes: list, files: list, connections: list) -> dict:
    """Generate a structured JSON report with summary statistics."""
    total_score = (
        sum(p["score"] for p in processes) +
        sum(f["score"] for f in files) +
        sum(c["score"] for c in connections)
    )

    # Overall risk level
    if total_score >= 30:   overall_risk = "CRITICAL"
    elif total_score >= 15: overall_risk = "HIGH"
    elif total_score >= 5:  overall_risk = "MEDIUM"
    elif total_score > 0:   overall_risk = "LOW"
    else:                   overall_risk = "CLEAN"

    report = {
        "meta": {
            "tool":         "ShadowWatch v2.0",
            "scan_time":    datetime.now().isoformat(),
            "scan_time_hr": datetime.now().strftime("%A %B %d, %Y at %I:%M %p"),
            "system":       get_system_info(),
        },
        "summary": {
            "overall_risk":        overall_risk,
            "total_threat_score":  total_score,
            "processes_flagged":   len(processes),
            "files_flagged":       len(files),
            "connections_flagged": len(connections),
        },
        "threats": {
            "processes":   processes,
            "files":       files,
            "connections": connections,
        }
    }

    filename = f"shadowwatch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    return report, filename


#  DISPLAY

def print_banner():
    print("""
╔══════════════════════════════════════════════╗
║        ShadowWatch - Activity Monitor        ║
║            Cybersecurity Scanner v2.0        ║
╚══════════════════════════════════════════════╝
""")


def print_section(title: str, items: list, formatter):
    
    print(f"\n  {title}")
    print("  " + "─" * 44)
    if not items:
        print("No threats detected")
    else:
        for item in items[:10]:  # Show top 10
            formatter(item)


def fmt_process(p: dict):
   
    print(f"[{p['severity'].upper():8}] {p['name']} (PID {p['pid']})")
    print(f"           Score: {p['score']} | User: {p['user']} | Started: {p['started']}")
    for r in p["reasons"]:
        print(f"           → {r}")
    print()


def fmt_file(f: dict):
   
    short_path = f["path"] if len(f["path"]) < 60 else "..." + f["path"][-57:]
    print(f"  [{f['severity'].upper():8}] {short_path}")
    print(f"           Score: {f['score']} | Size: {f['size_kb']}KB | Modified: {f['modified']}")
    if f.get("entropy"):
        print(f"           Entropy: {f['entropy']}/8.0")
    for r in f["reasons"]:
        print(f"           → {r}")
    print()


def fmt_connection(c: dict):
    
    print(f"  [{c['severity'].upper():8}] {c['process']} → {c['remote']}")
    print(f"           Score: {c['score']} | Status: {c['status']} | PID: {c['pid']}")
    if c["hostname"] != c["remote"].split(":")[0]:
        print(f"           Hostname: {c['hostname']}")
    for r in c["reasons"]:
        print(f"           → {r}")
    print()


def print_summary(report: dict, filename: str):
    s = report["summary"]
    risk = s["overall_risk"]
    
    print("\n" + "═" * 50)
    print(f"  OVERALL RISK: {risk}  (Score: {s['total_threat_score']})")
    print("═" * 50)
    print(f"  Processes flagged:   {s['processes_flagged']}")
    print(f"  Files flagged:       {s['files_flagged']}")
    print(f"  Connections flagged: {s['connections_flagged']}")
    print(f"\n Full report saved → {filename}")
    print("═" * 50 + "\n")


#  MAIN

def main():
    print_banner()
    sys_info = get_system_info()
    print(f"  Host: {sys_info['hostname']}  |  OS: {sys_info['os']}  |  Uptime: {sys_info['uptime_hrs']}h")
    print(f"  Scan started: {datetime.now().strftime('%H:%M:%S')}\n")

    print("  [1/3] Scanning processes...", end="", flush=True)
    processes = scan_processes()
    print(f" done. ({len(processes)} flagged)")

    print("  [2/3] Scanning files...", end="", flush=True)
    files = scan_files()
    print(f" done. ({len(files)} flagged)")

    print("  [3/3] Scanning network...", end="", flush=True)
    connections = scan_network()
    print(f" done. ({len(connections)} flagged)")

    # Print detailed findings
    print_section("SUSPICIOUS PROCESSES", processes, fmt_process)
    print_section("SUSPICIOUS FILES",     files,     fmt_file)
    print_section("SUSPICIOUS CONNECTIONS", connections, fmt_connection)

    # Generate and save report
    report, filename = generate_report(processes, files, connections)
    print_summary(report, filename)


if __name__ == "__main__":
    main()
