# core/scanner.py
# Uses nmap via python-nmap for accurate scanning

import nmap
import subprocess
import shutil
import time
from typing import Callable
from core.port_list import get_port_info, port_string

def nmap_available() -> bool:
    return shutil.which("nmap") is not None

def check_root() -> bool:
    import os
    return os.geteuid() == 0

def ping_sweep(
    ip_range: str,
    timeout: int = 2,
    force_pn: bool = False,
    progress_cb: Callable = None,
    stop_flag: Callable = None
) -> dict:
    """
    Phase 1 sweep. Two modes:
    - Normal: -sn ping sweep
    - force_pn: -Pn --open fast sweep (skip host discovery)

    Returns dict:
    {
      "alive": [ip, ...],
      "all_scanned": [ip, ...],
      "pn_used": bool,
      "suggested_pn": bool,  # True if 0 found on normal sweep
    }
    """
    nm = nmap.PortScanner()

    if force_pn:
        # -Pn: assume all hosts up, quick top-port scan to find open ones
        try:
            nm.scan(hosts=ip_range, arguments=f"-Pn --open -T4 -F")
        except nmap.PortScannerError as e:
            raise RuntimeError(f"nmap error: {e}")

        alive = []
        all_hosts = nm.all_hosts()
        for i, host in enumerate(all_hosts):
            if stop_flag and stop_flag():
                break
            # In -Pn mode hosts are listed if they have open ports
            state = nm[host].state()
            if state in ("up", "unknown"):
                alive.append(host)
            if progress_cb:
                progress_cb(host, host in alive, i + 1, len(all_hosts))

        return {
            "alive": alive,
            "all_scanned": all_hosts,
            "pn_used": True,
            "suggested_pn": False,
        }

    else:
        # Normal ping sweep
        try:
            nm.scan(hosts=ip_range, arguments=f"-sn -T4 --max-rtt-timeout {timeout}s")
        except nmap.PortScannerError as e:
            raise RuntimeError(f"nmap error: {e}")

        alive = []
        all_hosts = nm.all_hosts()
        for i, host in enumerate(all_hosts):
            if stop_flag and stop_flag():
                break
            is_up = nm[host].state() == "up"
            if is_up:
                alive.append(host)
            if progress_cb:
                progress_cb(host, is_up, i + 1, len(all_hosts))

        return {
            "alive": alive,
            "all_scanned": all_hosts,
            "pn_used": False,
            "suggested_pn": len(alive) == 0,  # Suggest -Pn if nothing found
        }


def deep_scan_host(
    ip: str,
    timing: str = "T3",
    stealth: bool = False,
    delay: float = 0.0,
    stop_flag: Callable = None
) -> list[dict]:
    """
    Full -p- scan on a SINGLE confirmed host.
    Finds ALL open ports including non-standard ones.
    This is the CTF report's Phase 3 — only run on the confirmed target.
    """
    nm = nmap.PortScanner()

    scan_type = "-sS" if (stealth and check_root()) else "-sT"
    delay_arg = f"--scan-delay {int(delay*1000)}ms" if delay > 0 else ""

    args = f"{scan_type} -sV -{timing} -p- --open --min-rate 5000 {delay_arg}".strip()

    try:
        nm.scan(hosts=ip, arguments=args)
    except nmap.PortScannerError as e:
        raise RuntimeError(f"Deep scan failed: {e}")

    return _extract_ports(nm, ip)


def _extract_ports(nm, ip: str) -> list[dict]:
    """Extract open port dicts from nmap result."""
    open_ports = []
    if ip not in nm.all_hosts():
        return open_ports
    for proto in nm[ip].all_protocols():
        for port in sorted(nm[ip][proto].keys()):
            pd = nm[ip][proto][port]
            if pd["state"] != "open":
                continue
            info    = get_port_info(port)
            product = pd.get("product", "")
            version = pd.get("version", "")
            extra   = pd.get("extrainfo", "")
            name    = pd.get("name", "") or info["service"]
            banner  = " ".join(x for x in [product, version, extra] if x)

            # tcpwrapped detection
            is_wrapped = "tcpwrapped" in name.lower()

            open_ports.append({
                "port":       port,
                "proto":      proto,
                "service":    name,
                "risk":       info["risk"],
                "note":       info["note"],
                "banner":     banner,
                "version":    version,
                "product":    product,
                "tcpwrapped": is_wrapped,
            })
    return open_ports


def scan_host(
    ip: str,
    stealth: bool = False,
    timing: str = "T3",
    delay: float = 0.0,
    progress_cb: Callable = None,
    stop_flag: Callable = None
) -> list[dict]:
    """
    Scan vuln-focused port list on a single host.
    - stealth=True uses SYN scan (-sS, requires root)
    - timing: T0-T5
    - delay: --scan-delay in seconds
    Returns list of open port dicts.
    """
    nm = nmap.PortScanner()
    ports = port_string()
    scan_type = "-sS -sV" if (stealth and check_root()) else "-sT -sV"
    delay_arg = f"--scan-delay {int(delay*1000)}ms" if delay > 0 else ""
    args = f"{scan_type} -{timing} --open -n {delay_arg}".strip()

    if progress_cb:
        progress_cb(ip, 0, False, 0, 1)
    try:
        nm.scan(hosts=ip, ports=ports, arguments=args)
    except nmap.PortScannerError as e:
        raise RuntimeError(f"nmap scan failed: {e}")

    return _extract_ports(nm, ip)


def get_os_info(ip: str) -> str:
    """
    Run nmap OS detection (requires root).
    Falls back to TTL guess if no root.
    """
    if not check_root():
        return _ttl_os_guess(ip)

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments="-O --osscan-guess -T4")
        if ip in nm.all_hosts():
            osmatch = nm[ip].get("osmatch", [])
            if osmatch:
                best = osmatch[0]
                return f"{best['name']} ({best['accuracy']}%)"
    except Exception:
        pass
    return _ttl_os_guess(ip)


def _ttl_os_guess(ip: str) -> str:
    import re
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:   return f"Linux/Unix (TTL {ttl})"
            if ttl <= 128:  return f"Windows (TTL {ttl})"
            return f"Network Device (TTL {ttl})"
    except Exception:
        pass
    return "Unknown"
