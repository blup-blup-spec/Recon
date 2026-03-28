# core/dns_intel.py
# DNS enumeration, zone transfer, TLS certificate intelligence

import socket
import ssl
import subprocess
import re
from datetime import datetime


# ── DNS Full Enumeration ───────────────────────────────────────────────────────
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]


def full_dns_enum(target: str) -> dict:
    """
    Full DNS enumeration on a domain or IP.
    Returns dict of record types and values.
    """
    result = {
        "target":      target,
        "records":     {},
        "zone_transfer": None,
        "new_hosts":   [],   # IPs discovered from MX/NS records
        "interesting": [],   # Anything worth flagging
    }

    is_ip = _is_ip(target)

    if is_ip:
        # Reverse DNS only
        try:
            hostname = socket.gethostbyaddr(target)[0]
            result["records"]["PTR"] = [hostname]
            result["interesting"].append(f"Reverse DNS: {target} → {hostname}")
        except Exception:
            result["records"]["PTR"] = []
        return result

    # A record
    try:
        ips = list(set(r[4][0] for r in socket.getaddrinfo(target, None)))
        result["records"]["A"] = ips
        result["new_hosts"].extend(ips)
    except Exception:
        result["records"]["A"] = []

    # All record types via dig
    for rtype in DNS_RECORD_TYPES:
        records = _dig(target, rtype)
        if records:
            result["records"][rtype] = records

    # MX — extract mail server IPs
    for mx in result["records"].get("MX", []):
        mx_host = mx.split()[-1].rstrip(".")
        try:
            mx_ip = socket.gethostbyname(mx_host)
            result["new_hosts"].append(mx_ip)
            result["interesting"].append(f"Mail server: {mx_host} → {mx_ip}")
        except Exception:
            pass

    # NS — nameservers (for zone transfer)
    ns_list = []
    for ns in result["records"].get("NS", []):
        ns_host = ns.strip().rstrip(".")
        ns_list.append(ns_host)

    # TXT — check for interesting content
    for txt in result["records"].get("TXT", []):
        txt_lower = txt.lower()
        if "spf" in txt_lower:
            result["interesting"].append(f"SPF record (may reveal mail infra): {txt[:100]}")
        if "v=dkim" in txt_lower:
            result["interesting"].append("DKIM configured")
        if any(k in txt_lower for k in ["internal", "vpn", "corp", "dev", "staging"]):
            result["interesting"].append(f"Interesting TXT: {txt[:100]}")

    # Zone transfer attempt
    if ns_list:
        zt = _zone_transfer(target, ns_list)
        result["zone_transfer"] = zt
        if zt.get("success"):
            result["interesting"].append(
                f"ZONE TRANSFER SUCCEEDED on {zt['nameserver']} — {len(zt['records'])} records dumped"
            )

    # CNAME — check for subdomain takeover candidates
    for cname in result["records"].get("CNAME", []):
        if any(provider in cname.lower() for provider in [
            "github.io", "herokuapp.com", "s3.amazonaws.com",
            "azurewebsites.net", "cloudfront.net", "fastly.net"
        ]):
            result["interesting"].append(
                f"CNAME → {cname} — possible subdomain takeover (third-party provider)"
            )

    return result


def _dig(domain: str, rtype: str) -> list:
    """Run dig and return parsed results."""
    try:
        result = subprocess.run(
            ["dig", "+short", domain, rtype],
            capture_output=True, text=True, timeout=8
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines
    except Exception:
        return []


def _zone_transfer(domain: str, nameservers: list) -> dict:
    """Attempt AXFR zone transfer against each nameserver."""
    for ns in nameservers[:3]:  # Try first 3 NS only
        try:
            result = subprocess.run(
                ["dig", f"@{ns}", domain, "AXFR", "+noall", "+answer"],
                capture_output=True, text=True, timeout=10
            )
            lines = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith(";")]
            if len(lines) > 2:
                return {
                    "success":     True,
                    "nameserver":  ns,
                    "records":     lines,
                    "raw":         result.stdout,
                }
        except Exception:
            continue
    return {"success": False, "nameserver": None, "records": []}


# ── TLS Certificate Intelligence ───────────────────────────────────────────────
def grab_tls_cert(ip: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Connect to TLS port and extract certificate intelligence.
    Returns dict with subject, SANs, issuer, expiry, org.
    """
    result = {
        "ip":          ip,
        "port":        port,
        "subject":     {},
        "issuer":      {},
        "san":         [],   # Subject Alternative Names
        "not_before":  None,
        "not_after":   None,
        "expired":     False,
        "self_signed": False,
        "interesting": [],
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()

                # Subject
                if cert.get("subject"):
                    result["subject"] = dict(x[0] for x in cert["subject"])

                # Issuer
                if cert.get("issuer"):
                    result["issuer"] = dict(x[0] for x in cert["issuer"])

                # SANs
                san_list = []
                for san_type, san_value in cert.get("subjectAltName", []):
                    san_list.append(f"{san_type}:{san_value}")
                    if san_type == "DNS":
                        result["interesting"].append(f"SAN hostname: {san_value}")
                result["san"] = san_list

                # Expiry
                not_before = cert.get("notBefore", "")
                not_after  = cert.get("notAfter", "")
                result["not_before"] = not_before
                result["not_after"]  = not_after

                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        if expiry < datetime.utcnow():
                            result["expired"] = True
                            result["interesting"].append(
                                f"EXPIRED certificate (expired {not_after}) — unmaintained system"
                            )
                    except Exception:
                        pass

                # Self-signed check
                subj = result["subject"].get("commonName", "")
                issr = result["issuer"].get("commonName", "")
                if subj and issr and subj == issr:
                    result["self_signed"] = True
                    result["interesting"].append("Self-signed certificate — lab/CTF/dev environment likely")

                # Internal hostnames in subject
                cn = result["subject"].get("commonName", "")
                if cn and any(k in cn.lower() for k in ["internal", "corp", "local", "intranet", "dev", "staging", "test"]):
                    result["interesting"].append(f"Internal hostname in cert CN: {cn}")

    except ssl.SSLError as e:
        result["interesting"].append(f"SSL error: {e} — possible decoy or misconfigured service")
    except Exception:
        pass

    return result


# ── HTTP Intelligence ──────────────────────────────────────────────────────────
def grab_http_intel(ip: str, port: int = 80, use_ssl: bool = False, timeout: float = 5.0) -> dict:
    """
    Grab HTTP headers + check robots.txt + sitemap.
    Returns dict with server, title, interesting headers, paths.
    """
    result = {
        "ip":          ip,
        "port":        port,
        "status":      None,
        "server":      "",
        "powered_by":  "",
        "title":       "",
        "cookies":     [],
        "robots_txt":  "",
        "interesting": [],
        "paths":       [],   # Paths found in robots.txt
    }

    scheme = "https" if use_ssl else "http"
    base = f"{ip}:{port}"

    # GET /
    headers, body, status = _http_get(ip, port, "/", use_ssl, timeout)
    result["status"] = status

    if not headers:
        return result

    result["server"]     = headers.get("server", headers.get("Server", ""))
    result["powered_by"] = headers.get("x-powered-by", headers.get("X-Powered-By", ""))

    # Title
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if title_match:
        result["title"] = title_match.group(1).strip()[:100]

    # Interesting headers
    for h, v in headers.items():
        hl = h.lower()
        if hl in ("x-powered-by", "x-aspnet-version", "x-generator"):
            result["interesting"].append(f"Tech header: {h}: {v}")
        if hl == "set-cookie":
            flags = v.lower()
            if "httponly" not in flags:
                result["interesting"].append(f"Cookie missing HttpOnly: {v[:60]}")
            if "secure" not in flags and use_ssl:
                result["interesting"].append(f"Cookie missing Secure flag: {v[:60]}")
        if hl == "server" and v:
            result["interesting"].append(f"Server: {v}")

    # Server version intelligence
    srv = result["server"].lower()
    if re.search(r"apache/2\.4\.4[89]", srv):
        result["interesting"].append("Apache 2.4.49/2.4.50 — CVE-2021-41773 path traversal RCE")
    if re.search(r"iis/6", srv):
        result["interesting"].append("IIS 6.0 — CVE-2017-7269 WebDAV buffer overflow RCE")

    # robots.txt
    _, robots_body, robots_status = _http_get(ip, port, "/robots.txt", use_ssl, timeout)
    if robots_status == 200 and robots_body:
        result["robots_txt"] = robots_body[:500]
        for line in robots_body.splitlines():
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    result["paths"].append(path)
                    result["interesting"].append(f"robots.txt Disallow: {path}")

    # 403 on common admin paths = exists but forbidden
    for path in ["/admin", "/administrator", "/login", "/dashboard", "/manager", "/wp-admin"]:
        _, _, s = _http_get(ip, port, path, use_ssl, timeout)
        if s == 403:
            result["interesting"].append(f"Path exists (403 Forbidden): {path}")
            result["paths"].append(path)
        elif s == 200:
            result["interesting"].append(f"Path accessible (200 OK): {path}")
            result["paths"].append(path)

    return result


def _http_get(ip: str, port: int, path: str, use_ssl: bool, timeout: float):
    """Raw HTTP GET. Returns (headers_dict, body_str, status_code)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)

        request = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 50000:
                break
        sock.close()

        text = response.decode("utf-8", errors="replace")
        header_section, _, body = text.partition("\r\n\r\n")
        lines = header_section.splitlines()

        status = 0
        if lines:
            m = re.match(r"HTTP/[\d.]+ (\d+)", lines[0])
            if m:
                status = int(m.group(1))

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()

        return headers, body, status

    except Exception:
        return {}, "", 0


def _is_ip(target: str) -> bool:
    try:
        socket.inet_aton(target)
        return True
    except Exception:
        return False
