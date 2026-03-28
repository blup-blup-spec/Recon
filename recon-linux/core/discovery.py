# core/discovery.py

import socket
import subprocess
import re


def dns_lookup(target: str) -> dict:
    result = {"hostname": "", "ip": target}
    try:
        socket.inet_aton(target)
        # It's an IP — reverse lookup
        try:
            result["hostname"] = socket.gethostbyaddr(target)[0]
        except Exception:
            result["hostname"] = ""
    except socket.error:
        # It's a hostname
        result["hostname"] = target
        try:
            result["ip"] = socket.gethostbyname(target)
        except Exception:
            result["ip"] = ""
    return result


def whois_lookup(target: str) -> str:
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout or ""
        key_fields = []
        for line in output.splitlines():
            low = line.lower()
            if any(k in low for k in [
                "registrant", "orgname", "org:", "organization",
                "country", "netrange", "cidr", "inetnum",
                "netname", "descr:", "admin", "registrar",
                "created", "updated", "expires", "abuse"
            ]):
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("%") and not cleaned.startswith("#"):
                    key_fields.append(cleaned)
        return "\n".join(key_fields[:25]) if key_fields else "No WHOIS data"
    except FileNotFoundError:
        return "whois not installed (apt install whois)"
    except subprocess.TimeoutExpired:
        return "WHOIS timed out"
    except Exception as e:
        return f"WHOIS error: {e}"


def discover_host(ip: str) -> dict:
    dns = dns_lookup(ip)
    whois = whois_lookup(ip)
    return {
        "ip":       dns["ip"] or ip,
        "hostname": dns["hostname"],
        "whois":    whois,
    }
