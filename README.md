# RECON OPERATOR v3 — Tactical Network Intelligence

A professional, GUI-driven network reconnaissance and intelligence gathering system designed for deep penetration testing and CTF workflows. Built with **PyQt6** and leveraging the power of **nmap**, this tool automates a rigorous 6-phase reconnaissance methodology to ensure no entry point is missed.

## 🛡️ Tactical Reconnaissance Methodology

The system follows a tiered approach to network intelligence, ensuring stealth and comprehensive coverage:

### Phase 1: Ping Sweep (Presence Identification)
- Rapidly identify alive hosts in the target CIDR/Range.
- Automatically suggests `-Pn` fallback if ICMP filtering is detected.

### Phase 2: Target Identification & OS Fingerprinting
- Resolves hostnames and fingerprints the operating system.
- Includes a **TTL-based fallback guess** if root privileges are unavailable for standard Nmap OS detection.

### Phase 3: Vulnerability-Focused Port Scanning
- Targets a curated list of high-risk ports (web, database, remote access, file transfer).
- Supports **SYN Stealth** scans for reduced detection profile.

### Phase 4: Intelligence Gathering & CVE Matching
- **DNS Extraction**: Performs zone transfers and enumerates subdomains.
- **TLS/SSL Intel**: Extracts Certificate Authorities and SAN (Subject Alternative Names).
- **HTTP/Web Surface**: Probes headers, server versions, and `robots.txt`.
- **CVE Matching**: Real-time matching of service banners against known vulnerability databases.

### Phase 5: Deep Enumeration (The "Phase 3" Detail)
- Initiates a full **65,535 port scan** on confirmed high-priority targets.
- Identifies **non-standard port mappings** (e.g., SMB on 4445 or Redis on non-standard ports).

### Phase 6: Reporting & Case Management
- Generates professional **Markdown reports**.
- Integrates with **Obsidian Vaults** for long-term case tracking and internal knowledge bases.

---

## 🚀 Key Features

- **IDS/Firewall Detection**: Automatically alerts the operator if responses are being dropped, suggesting a move to slower timing profiles (T0/T1).
- **Non-Standard Port Hints**: Intelligent detection of common services shifted to alternative ports.
- **Triage Scoring**: 0-100 scoring system to prioritize high-value targets based on exposed services.
- **Modern UI**: A sleek, dark-mode terminal interface for high-performance operations.

## 🛠️ Installation

### Dependencies
Ensure you have Nmap and the necessary system tools installed:
```bash
sudo apt install nmap whois dnsutils
```

### Python Setup
```bash
pip install PyQt6 python-nmap
```

## 📋 usage

1. **Launch**: `python3 main.py`
2. **Configure**: Enter your target IP or CIDR.
3. **Scan**: Hit `EXECUTE SCAN` to initiate the first 4 phases.
4. **Enumerate**: Select a host and hit `DEEP SCAN` for full coverage.
5. **Report**: Check the `REPORT` tab or your connected Obsidian Vault.

---
*Created for tactical network reconnaissance and advanced security auditing.*
