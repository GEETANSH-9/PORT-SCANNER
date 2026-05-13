import nmap
import requests
import json
import re
import time
import sqlite3
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple, List, Optional


# CONFIG

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = ""          #  NVD API key 
                           #  https://nvd.nist.gov/developers/request-an-api-key
DB_PATH = "scan_history.db"

# Cache for CVE results
cve_cache = {}

# -------------------------------
# INPUT VALIDATION
# -------------------------------
def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validates a scan target (IP address or hostname).
    Returns (is_valid, cleaned_target_or_error_message).
    """
    target = target.strip()

    if not target:
        return False, "Empty target"

    # Reject obviously dangerous patterns (shell injection attempts)
    forbidden = [";", "&", "|", "`", "$", "(", ")", "{", "}", "<", ">", "\n", "\r"]
    for char in forbidden:
        if char in target:
            return False, f"Invalid character '{char}' in target"

    # Try parsing as IP address (v4 or v6)
    try:
        ipaddress.ip_address(target)
        return True, target
    except ValueError:
        pass

    # Try parsing as CIDR range
    try:
        ipaddress.ip_network(target, strict=False)
        return True, target
    except ValueError:
        pass

    # Validate as hostname (RFC 1123)
    hostname_regex = re.compile(
        r"^(?!-)[A-Z\d\-]{1,63}(?<!-)(\.[A-Z\d\-]{1,63})*\.?$",
        re.IGNORECASE
    )
    if hostname_regex.match(target):
        return True, target

    return False, f"'{target}' is not a valid IP address, CIDR range, or hostname"


def validate_targets(targets_input) -> Tuple[List, List]:
    """
    Validates a list or comma-separated string of targets.
    Returns (valid_targets, errors).
    """
    if isinstance(targets_input, str):
        raw = [t.strip() for t in targets_input.split(",") if t.strip()]
    else:
        raw = targets_input

    valid, errors = [], []
    for t in raw:
        ok, result = validate_target(t)
        if ok:
            valid.append(result)
        else:
            errors.append(result)

    return valid, errors



# CVSS-BASED RISK SCORING

CVSS_SEVERITY_MAP = {
    "CRITICAL": ("CRITICAL", 9.0),
    "HIGH":     ("HIGH",     7.0),
    "MEDIUM":   ("MEDIUM",   4.0),
    "LOW":      ("LOW",      0.1),
    "NONE":     ("LOW",      0.0),
}

# Fallback static risk hints for common ports (used when no CVE score available)
PORT_HINTS = {
    21:   ("HIGH",     "FTP — unencrypted file transfer"),
    22:   ("MEDIUM",   "SSH — brute-force risk"),
    23:   ("CRITICAL", "Telnet — plaintext remote access"),
    25:   ("MEDIUM",   "SMTP — check for open relay"),
    53:   ("MEDIUM",   "DNS — amplification attack risk"),
    80:   ("MEDIUM",   "HTTP — traffic unencrypted"),
    135:  ("HIGH",     "RPC — Windows vulnerability exposure"),
    139:  ("HIGH",     "NetBIOS — information leakage"),
    443:  ("LOW",      "HTTPS — encrypted web traffic"),
    445:  ("CRITICAL", "SMB — ransomware / EternalBlue target"),
    3389: ("HIGH",     "RDP — exposed remote desktop"),
    5900: ("HIGH",     "VNC — remote desktop exposure"),
    8080: ("MEDIUM",   "HTTP-alt — often misconfigured"),
}


def risk_from_cvss(cvss_score: float) -> str:
    """Convert a numeric CVSS score to a risk label string."""
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0.0:
        return "LOW"
    else:
        return "LOW"


def risk_score(port: int, service: str, cvss_score: float = None) -> str:
    """
    Dynamic risk scoring:
    1. If we have a real CVSS score from NVD, use it.
    2. Otherwise fall back to port-based hints.
    3. If port unknown, return LOW.
    """
    if cvss_score is not None and cvss_score > 0:
        level = risk_from_cvss(cvss_score)
        hint = PORT_HINTS.get(port, ("", ""))[1]
        desc = f" — {hint}" if hint else ""
        return f"{level} (CVSS {cvss_score:.1f}){desc}"

    if port in PORT_HINTS:
        level, hint = PORT_HINTS[port]
        return f"{level} — {hint}"

    return "LOW"



# CVE FETCH WITH RETRY + API KEY

def get_cve(service: str) -> Tuple[str, float]:
    """
    Fetch top CVE for a service from NVD.
    Returns (cve_id, cvss_score).
    Retries up to 3 times with exponential backoff on rate-limit errors.
    """
    if not service or service in ("unknown", ""):
        return "No CVE found", 0.0

    if service in cve_cache:
        return cve_cache[service]

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {"keywordSearch": service, "resultsPerPage": 1}

    for attempt in range(3):
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=5)

            if resp.status_code == 429:
                wait = 2 ** attempt * 6   # 6s, 12s, 24s
                time.sleep(wait)
                continue

            if resp.status_code != 200:
                result = ("API error", 0.0)
                break

            data = resp.json()
            vulns = data.get("vulnerabilities", [])

            if not vulns:
                result = ("No CVE found", 0.0)
                break

            cve_item = vulns[0]["cve"]
            cve_id = cve_item["id"]

            # Extract CVSS v3.1 score, fall back to v2
            cvss_score = 0.0
            metrics = cve_item.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            result = (cve_id, round(cvss_score, 1))
            break

        except requests.exceptions.Timeout:
            result = ("Timeout", 0.0)
            break
        except Exception:
            result = ("Error", 0.0)
            break
    else:
        result = ("Rate limited", 0.0)

    cve_cache[service] = result
    return result



# SCAN HISTORY (SQLite)

def init_db():
    """Create the scan history database and tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            target   TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id  INTEGER NOT NULL,
            host     TEXT,
            port     INTEGER,
            service  TEXT,
            version  TEXT,
            cve      TEXT,
            risk     TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)
    conn.commit()
    conn.close()


def save_scan(target: str, results: list) -> int:
    """Persist scan results to history DB. Returns the new scan_id."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("INSERT INTO scans (target, scanned_at) VALUES (?, ?)", (target, now))
    scan_id = c.lastrowid
    for r in results:
        c.execute("""
            INSERT INTO scan_results (scan_id, host, port, service, version, cve, risk)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, r["Host"], r["Port"], r["Service"], r["Version"], r["CVE"], r["Risk"]))
    conn.commit()
    conn.close()
    return scan_id


def get_scan_history(limit: int = 20) -> list:
    """Return a list of past scan summaries."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT s.id, s.target, s.scanned_at, COUNT(r.id) as total_ports
        FROM scans s
        LEFT JOIN scan_results r ON r.scan_id = s.id
        GROUP BY s.id
        ORDER BY s.id DESC
        LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return [{"scan_id": r[0], "target": r[1], "scanned_at": r[2], "total_ports": r[3]} for r in rows]


def get_scan_results(scan_id: int) -> list:
    """Return all results for a specific scan_id."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT host, port, service, version, cve, risk
        FROM scan_results WHERE scan_id = ?
    """, (scan_id,))
    rows = c.fetchall()
    conn.close()
    return [{"Host": r[0], "Port": r[1], "Service": r[2], "Version": r[3], "CVE": r[4], "Risk": r[5]} for r in rows]


def diff_scans(old_scan_id: int, new_results: list) -> dict:
    """
    Compare new scan results against a previous scan.
    Returns dict with: new_ports, closed_ports, changed_ports.
    """
    old_results = get_scan_results(old_scan_id)
    old_ports = {(r["Host"], r["Port"]): r for r in old_results}
    new_ports = {(r["Host"], r["Port"]): r for r in new_results}

    newly_opened = [new_ports[k] for k in new_ports if k not in old_ports]
    now_closed   = [old_ports[k] for k in old_ports if k not in new_ports]
    changed      = [
        {"old": old_ports[k], "new": new_ports[k]}
        for k in new_ports
        if k in old_ports and old_ports[k]["Risk"] != new_ports[k]["Risk"]
    ]

    return {
        "new_ports":    newly_opened,
        "closed_ports": now_closed,
        "changed_ports": changed,
    }


def get_last_scan_id_for_target(target: str) -> Optional[int]:
    """Return the most recent scan_id for a given target, or None."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1
    """, (target,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None



# SINGLE TARGET SCAN

def scan_target(target: str, fast_mode: bool = False) -> list:
    # Validate before scanning
    ok, result = validate_target(target)
    if not ok:
        raise ValueError(f"Invalid target: {result}")

    scanner = nmap.PortScanner()

    if fast_mode:
        scanner.scan(target, arguments="-sT --min-rate 1000 --max-retries 2")
    else:
        scanner.scan(target, arguments="-sT -sV")

    results = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                service = scanner[host][proto][port]["name"]
                version = scanner[host][proto][port].get("version", "")

                if fast_mode:
                    cve_id, cvss_score = "Skipped (fast mode)", 0.0
                else:
                    cve_id, cvss_score = get_cve(service)

                risk = risk_score(port, service, cvss_score if not fast_mode else None)

                results.append({
                    "Host":    host,
                    "Port":    port,
                    "Service": service,
                    "Version": version,
                    "CVE":     cve_id,
                    "CVSS":    cvss_score,
                    "Risk":    risk,
                })

    return results



# MULTI-TARGET SCANNING

def scan_multiple_targets(targets, fast_mode: bool = False) -> list:
    all_results = []
    if isinstance(targets, str):
        targets = [targets]
    valid, errors = validate_targets(targets)
    for err in errors:
        print(f"[!] Skipping: {err}")
    for target in valid:
        print(f"\n[+] Scanning {target}")
        all_results.extend(scan_target(target, fast_mode))
    return all_results


def threaded_scan(targets, fast_mode: bool = False) -> list:
    if isinstance(targets, str):
        targets = [targets]
    valid, errors = validate_targets(targets)
    for err in errors:
        print(f"[!] Skipping: {err}")
    if not valid:
        return []

    print("\n[+] Starting Fast Parallel Scan...\n")
    all_results = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        # Consume results INSIDE the with block to catch exceptions properly
        futures = list(executor.map(lambda t: scan_target(t, fast_mode), valid))

    for res in futures:
        all_results.extend(res)

    return all_results



# REPORT GENERATION

def generate_report(results: list) -> str:
    filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    return filename



# SUMMARY

def summarize(results: list) -> dict:
    total    = len(results)
    critical = sum(1 for r in results if "CRITICAL" in r["Risk"])
    high     = sum(1 for r in results if "HIGH"     in r["Risk"])
    return {"total": total, "critical": critical, "high": high}



# CLI MODE

if __name__ == "__main__":
    targets = ["scanme.nmap.org", "127.0.0.1"]

    print("\nChoose Scan Mode:")
    print("1. Sequential Scan")
    print("2. Threaded Scan (Fast)")
    print("3. Ultra Fast Scan (No CVE)")

    choice = input("Enter choice (1/2/3): ")

    if choice == "1":
        results = scan_multiple_targets(targets)
    elif choice == "2":
        results = threaded_scan(targets)
    else:
        results = threaded_scan(targets, fast_mode=True)

    print("\n[+] Scan Results:\n")
    for r in results:
        print(f"{r['Host']} | {r['Port']} | {r['Service']} | {r['Risk']} | {r['CVE']} | CVSS: {r['CVSS']}")

    # Save to history
    combined_target = ", ".join(targets)
    scan_id = save_scan(combined_target, results)
    print(f"\n[+] Scan saved to history (ID: {scan_id})")

    file = generate_report(results)
    print(f"[+] Report saved: {file}")