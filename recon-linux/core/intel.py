# core/intel.py
# Banner CVE matching, version intelligence, triage scoring, decoy detection

import re
import ssl
import socket
from datetime import datetime

# ── CVE / Version Intelligence Database ───────────────────────────────────────
# Format: (regex_pattern, cve_id, description, severity)
BANNER_CVE_DB = [
    # OpenSSH
    (r"openssh[_ ]([0-9]+\.[0-9]+)", "CVE-2018-15473", "User enumeration via timing attack", "MEDIUM"),
    (r"openssh[_ ][1-6]\.", "CVE-2016-0777", "Roaming feature memory leak — credential exposure", "HIGH"),
    (r"openssh[_ ][1-7]\.[0-3]", "CVE-2019-6111", "scp client arbitrary file write", "MEDIUM"),

    # Apache
    (r"apache[/ ]2\.4\.4[89]", "CVE-2021-41773", "Path traversal + RCE (one of worst 2021 vulns)", "CRITICAL"),
    (r"apache[/ ]2\.4\.50", "CVE-2021-42013", "Path traversal bypass for 41773 patch", "CRITICAL"),
    (r"apache[/ ]2\.[0-3]\.", "CVE-2017-7679", "mod_mime buffer overread", "HIGH"),
    (r"apache[/ ]2\.4\.[0-2][0-9]", "CVE-2017-9798", "Optionsbleed — memory leak via OPTIONS", "MEDIUM"),

    # nginx
    (r"nginx[/ ]1\.[0-9]\.", "CVE-2013-2028", "Stack overflow in chunked transfer (old nginx)", "HIGH"),
    (r"nginx[/ ]1\.1[0-5]\.", "CVE-2017-7529", "Integer overflow — info leak via Range header", "MEDIUM"),

    # IIS
    (r"iis[/ ]6\.0", "CVE-2017-7269", "IIS 6.0 WebDAV buffer overflow — RCE", "CRITICAL"),
    (r"iis[/ ]5\.", "CVE-2001-0500", "IIS 5 .printer ISAPI overflow — classic RCE", "CRITICAL"),

    # vsftpd
    (r"vsftpd 2\.3\.4", "CVE-2011-2523", "Backdoor — connect port 6200 after ':)' in username", "CRITICAL"),
    (r"vsftpd 2\.[0-2]\.", "CVE-2011-0762", "vsftpd DoS via STAT command", "MEDIUM"),

    # ProFTPD
    (r"proftpd 1\.3\.[0-3]", "CVE-2010-4221", "ProFTPD remote code execution via TELNET_IAC", "CRITICAL"),
    (r"proftpd 1\.3\.[3-4]", "CVE-2011-4130", "Use-after-free in response pool", "HIGH"),

    # Samba / SMB
    (r"samba 3\.[0-5]\.", "CVE-2017-7494", "SambaCry — RCE via writable share (EternalRed)", "CRITICAL"),
    (r"samba [1-3]\.", "CVE-2010-2063", "Samba chain_reply buffer overflow", "HIGH"),

    # MySQL
    (r"mysql[/ ]5\.[0-5]\.", "CVE-2012-2122", "Auth bypass via timing — any password works sometimes", "CRITICAL"),
    (r"mysql[/ ]5\.[0-6]\.", "CVE-2016-6662", "MySQL config injection — RCE as root", "CRITICAL"),

    # Redis
    (r"redis[/ ][0-6]\.", "CVE-2022-0543", "Lua sandbox escape — RCE (Debian/Ubuntu packages)", "CRITICAL"),

    # Elasticsearch
    (r"elasticsearch[/ ][0-1]\.", "CVE-2014-3120", "Dynamic script RCE (no auth)", "CRITICAL"),
    (r"elasticsearch[/ ]1\.[0-3]", "CVE-2015-1427", "Groovy sandbox escape — RCE", "CRITICAL"),

    # MongoDB
    (r"mongodb[/ ][1-3]\.", "CVE-2013-1892", "MongoDB server-side JS injection", "HIGH"),

    # PHP
    (r"php[/ ]5\.[0-3]\.", "CVE-2012-1823", "PHP-CGI query string RCE — trivially exploitable", "CRITICAL"),
    (r"php[/ ]7\.[0-1]\.", "CVE-2019-11043", "PHP-FPM + nginx buffer underflow RCE", "CRITICAL"),
    (r"php[/ ]5\.[0-6]\.", "CVE-2015-6835", "Use-after-free in session deserialize", "HIGH"),

    # Tomcat
    (r"apache tomcat[/ ][0-8]\.", "CVE-2019-0232", "CGI Servlet RCE on Windows", "CRITICAL"),
    (r"apache tomcat[/ ]9\.0\.[0-3][0-9]", "CVE-2020-1938", "Ghostcat — AJP file read/include", "CRITICAL"),
    (r"apache tomcat[/ ][0-7]\.", "CVE-2017-12617", "JSP upload bypass — RCE", "CRITICAL"),

    # OpenSSL
    (r"openssl 1\.0\.[01]", "CVE-2014-0160", "Heartbleed — memory read, private key leak", "CRITICAL"),
    (r"openssl 1\.0\.[0-2]", "CVE-2016-0800", "DROWN — SSLv2 cross-protocol attack", "HIGH"),

    # Telnet
    (r"telnet", None, "Plaintext protocol — credentials transmitted in cleartext", "CRITICAL"),

    # Generic old versions
    (r"windows server 200[0-3]", "CVE-2008-4250", "MS08-067 — NetAPI buffer overflow, EternalBlue era", "CRITICAL"),
    (r"windows server 2008", "CVE-2017-0144", "MS17-010 EternalBlue — SMB RCE", "CRITICAL"),
]


def check_banner_cves(banner: str, service: str = "") -> list[dict]:
    """
    Match banner string against CVE database.
    Returns list of matching CVEs.
    """
    if not banner:
        return []

    combined = f"{banner} {service}".lower()
    hits = []

    for pattern, cve, desc, severity in BANNER_CVE_DB:
        if re.search(pattern, combined, re.IGNORECASE):
            hits.append({
                "cve":      cve or "NO-CVE",
                "desc":     desc,
                "severity": severity,
            })

    return hits


# ── Triage Scoring ─────────────────────────────────────────────────────────────
DECOY_INDICATORS = [
    "troll", "nope", "lol", "gotcha", "honeypot",
    "ha ha", "nice try", "wrong", "bait", "fake",
    "void", "nothing here", "go away", "bye"
]

HIGH_VALUE_PORTS = {21, 22, 23, 445, 3389, 3306, 5432, 6379, 27017, 9200, 2375, 10250}
NONSTANDARD_HINTS = {
    4445: ("SMB", 445, "smbclient //host/share -p 4445 -U user"),
    4446: ("SMB", 445, "smbclient //host/share -p 4446 -U user"),
    2222: ("SSH", 22,  "ssh user@host -p 2222"),
    222:  ("SSH", 22,  "ssh user@host -p 222"),
    2022: ("SSH", 22,  "ssh user@host -p 2022"),
    8022: ("SSH", 22,  "ssh user@host -p 8022"),
    2121: ("FTP", 21,  "ftp host 2121"),
    2020: ("FTP", 21,  "ftp host 2020"),
    8888: ("HTTP", 80, "curl http://host:8888/"),
    9090: ("HTTP", 80, "curl http://host:9090/"),
    3000: ("HTTP", 80, "curl http://host:3000/  (common: Grafana, Node)"),
    5000: ("HTTP", 80, "curl http://host:5000/  (common: Flask dev)"),
    8000: ("HTTP", 80, "curl http://host:8000/"),
    1337: ("CTF",  0,  "Classic CTF port — manual investigation"),
    31337: ("CTF", 0,  "Elite CTF port — manual investigation"),
    9999: ("CTF",  0,  "Common CTF service port"),
    4444: ("Metasploit", 0, "Default Metasploit handler — possible backdoor/C2"),
}


def score_host(open_ports: list[dict], banners: list[str] = None) -> dict:
    """
    Score a host 0-100 for likelihood of being the real target.
    Returns score + reasoning.
    """
    score = 0
    reasons = []
    warnings = []

    port_nums = {p["port"] for p in open_ports}
    all_banners = " ".join(p.get("banner", "") for p in open_ports).lower()

    # Port diversity — more diverse = more real
    if len(open_ports) >= 5:
        score += 25
        reasons.append(f"{len(open_ports)} open ports — high surface area")
    elif len(open_ports) >= 3:
        score += 15
        reasons.append(f"{len(open_ports)} open ports")
    elif len(open_ports) == 1:
        score += 5
        warnings.append("Single open port — possible decoy/honeypot")
    elif len(open_ports) == 0:
        return {"score": 0, "label": "DEAD", "reasons": ["No open ports"], "warnings": [], "priority": "SKIP"}

    # High value ports present
    hv = port_nums & HIGH_VALUE_PORTS
    if hv:
        score += 20
        reasons.append(f"High-value ports: {', '.join(str(p) for p in sorted(hv))}")

    # Non-standard ports — CTF/custom service indicator
    ns = [p for p in open_ports if p["port"] in NONSTANDARD_HINTS]
    if ns:
        score += 15
        reasons.append(f"Non-standard ports detected: {', '.join(str(p['port']) for p in ns)}")

    # Decoy indicators in banners
    for indicator in DECOY_INDICATORS:
        if indicator in all_banners:
            score -= 40
            warnings.append(f"Decoy indicator in banner: '{indicator}'")
            break

    # SSL error on non-SSL port = decoy
    if "ssl" in all_banners and not any(p["port"] in (443, 8443, 993, 995, 465) for p in open_ports):
        score -= 20
        warnings.append("SSL error on non-SSL port — likely decoy/misconfiguration")

    # tcpwrapped on all ports = filtered, not necessarily decoy
    wrapped = [p for p in open_ports if "tcpwrapped" in p.get("service", "").lower()]
    if len(wrapped) == len(open_ports) and open_ports:
        score += 5
        warnings.append("All ports tcpwrapped — manual investigation needed")

    # Generic-only ports (22, 80, 443 only) = possibly dead end
    generic = {22, 80, 443}
    if port_nums and port_nums.issubset(generic):
        score -= 15
        warnings.append("Only generic ports (22/80/443) — limited attack surface")

    # FTP is almost always a real entry point in CTFs
    if 21 in port_nums:
        score += 15
        reasons.append("FTP port 21 — likely entry point (check anonymous login)")

    score = max(0, min(100, score))

    if score >= 70:
        label, priority = "HIGH VALUE", "PRIMARY"
    elif score >= 40:
        label, priority = "INVESTIGATE", "SECONDARY"
    elif score >= 20:
        label, priority = "LOW PRIORITY", "TERTIARY"
    else:
        label, priority = "LIKELY DECOY", "SKIP"

    return {
        "score":    score,
        "label":    label,
        "priority": priority,
        "reasons":  reasons,
        "warnings": warnings,
    }


def get_nonstandard_hint(port: int) -> dict:
    """Return hint if this port is a non-standard version of a known service."""
    if port in NONSTANDARD_HINTS:
        service, std_port, cmd = NONSTANDARD_HINTS[port]
        return {
            "is_nonstandard": True,
            "likely_service": service,
            "standard_port":  std_port,
            "hint":           cmd,
        }
    return {"is_nonstandard": False}


def detect_ids_evasion_needed(response_times: list[float]) -> bool:
    """
    Check if response times suggest IDS/firewall interference.
    If last N responses are all timeouts after normal responses — likely banned.
    """
    if len(response_times) < 10:
        return False
    last_10 = response_times[-10:]
    # If last 10 are all max timeout and earlier ones weren't
    if all(t >= 2.0 for t in last_10) and not all(t >= 2.0 for t in response_times[:10]):
        return True
    return False
