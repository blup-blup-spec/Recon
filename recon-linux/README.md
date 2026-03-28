# RECON OPERATOR — Linux Edition

Industrial HUD recon tool. nmap-backed. PyQt6 GUI.

## Install

```bash
# System deps
sudo apt install nmap whois python3-pip

# Python deps
pip install PyQt6 python-nmap

# Run
python3 main.py

# For SYN stealth scan (more accurate, less detectable)
sudo python3 main.py
```

## Timing Profiles

| Profile | Use When |
|---------|----------|
| T0 Paranoid | IDS evasion, very slow |
| T1 Sneaky | Slow, mostly avoids detection |
| T2 Polite | Default — respectful, reliable |
| T3 Normal | Faster, acceptable noise |
| T4 Aggressive | CTF / lab — fast |

## Port Coverage (~70 ports)

FTP, SSH, Telnet, SMTP, DNS, HTTP/S, SMB, RDP, RPC,
LDAP/AD, MSSQL, Oracle, MySQL, PostgreSQL, MongoDB,
Redis, Elasticsearch, CouchDB, Neo4j, InfluxDB,
Kafka, RabbitMQ, Cassandra, Memcached, Zookeeper,
VNC, NFS, Rsync, TFTP, Docker, Kubernetes/etcd,
Kubelet, SNMP, IPMI, Modbus, Siemens S7, BACnet,
Cisco Smart Install, Metasploit handler, IRC, Tor

## Project Structure

```
recon-linux/
├── main.py              # GUI entry point
├── core/
│   ├── port_list.py     # ~70 vuln ports with risk tags
│   ├── scanner.py       # nmap ping sweep + port scan
│   └── discovery.py     # WHOIS + DNS
├── utils/
│   ├── cidr.py          # IP/CIDR/range expansion
│   └── reporter.py      # Markdown → Obsidian
└── requirements.txt
```

## Legal

Only scan systems you own or have written permission to test.
