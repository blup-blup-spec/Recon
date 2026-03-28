# core/port_list.py

VULN_PORTS = [
    # FTP
    {"port": 21,    "service": "FTP",           "risk": "HIGH",     "note": "Anonymous login / plaintext creds"},
    {"port": 990,   "service": "FTPS",          "risk": "MEDIUM",   "note": "FTP over SSL"},
    # SSH/Telnet
    {"port": 22,    "service": "SSH",           "risk": "MEDIUM",   "note": "Brute force / weak keys"},
    {"port": 23,    "service": "Telnet",        "risk": "CRITICAL", "note": "Plaintext — always vuln"},
    {"port": 2222,  "service": "SSH-Alt",       "risk": "MEDIUM",   "note": "Alternate SSH"},
    # Mail
    {"port": 25,    "service": "SMTP",          "risk": "MEDIUM",   "note": "Open relay / user enum"},
    {"port": 110,   "service": "POP3",          "risk": "MEDIUM",   "note": "Plaintext email"},
    {"port": 143,   "service": "IMAP",          "risk": "MEDIUM",   "note": "Plaintext / cred sniff"},
    {"port": 465,   "service": "SMTPS",         "risk": "LOW",      "note": "SMTP over SSL"},
    {"port": 587,   "service": "SMTP-Sub",      "risk": "MEDIUM",   "note": "Check open relay"},
    {"port": 993,   "service": "IMAPS",         "risk": "LOW",      "note": "IMAP SSL"},
    {"port": 995,   "service": "POP3S",         "risk": "LOW",      "note": "POP3 SSL"},
    # DNS
    {"port": 53,    "service": "DNS",           "risk": "MEDIUM",   "note": "Zone transfer / amplification"},
    # HTTP/Web
    {"port": 80,    "service": "HTTP",          "risk": "MEDIUM",   "note": "Unencrypted web traffic"},
    {"port": 443,   "service": "HTTPS",         "risk": "LOW",      "note": "Check TLS version"},
    {"port": 8000,  "service": "HTTP-Dev",      "risk": "MEDIUM",   "note": "Dev server"},
    {"port": 8080,  "service": "HTTP-Alt",      "risk": "MEDIUM",   "note": "Proxy / admin panels"},
    {"port": 8443,  "service": "HTTPS-Alt",     "risk": "MEDIUM",   "note": "Alt HTTPS / less hardened"},
    {"port": 8888,  "service": "Jupyter",       "risk": "HIGH",     "note": "Jupyter notebook often exposed"},
    {"port": 9090,  "service": "Prometheus",    "risk": "HIGH",     "note": "Metrics — often unauth"},
    # Windows/SMB
    {"port": 135,   "service": "RPC",           "risk": "HIGH",     "note": "Lateral movement vector"},
    {"port": 137,   "service": "NetBIOS-NS",    "risk": "MEDIUM",   "note": "Info leak / LLMNR poison"},
    {"port": 138,   "service": "NetBIOS-DGM",   "risk": "MEDIUM",   "note": "Datagram info leak"},
    {"port": 139,   "service": "NetBIOS-SSN",   "risk": "HIGH",     "note": "SMB over NetBIOS"},
    {"port": 445,   "service": "SMB",           "risk": "CRITICAL", "note": "EternalBlue / ransomware"},
    {"port": 593,   "service": "RPC-HTTP",      "risk": "HIGH",     "note": "RPC over HTTP"},
    {"port": 3389,  "service": "RDP",           "risk": "CRITICAL", "note": "BlueKeep / brute force"},
    # LDAP/AD
    {"port": 389,   "service": "LDAP",          "risk": "HIGH",     "note": "AD enum / null bind"},
    {"port": 636,   "service": "LDAPS",         "risk": "MEDIUM",   "note": "Check null bind"},
    {"port": 3268,  "service": "GlobalCatalog", "risk": "HIGH",     "note": "Full AD forest enum"},
    # Databases
    {"port": 1433,  "service": "MSSQL",         "risk": "CRITICAL", "note": "xp_cmdshell RCE / sa account"},
    {"port": 1521,  "service": "Oracle",        "risk": "CRITICAL", "note": "TNS poison / default creds"},
    {"port": 3306,  "service": "MySQL",         "risk": "CRITICAL", "note": "Anon login / exposed DB"},
    {"port": 5432,  "service": "PostgreSQL",    "risk": "HIGH",     "note": "Trust auth / default creds"},
    {"port": 6379,  "service": "Redis",         "risk": "CRITICAL", "note": "No-auth default — RCE via config"},
    {"port": 9200,  "service": "Elasticsearch", "risk": "CRITICAL", "note": "No-auth — full data dump"},
    {"port": 9300,  "service": "Elastic-Node",  "risk": "HIGH",     "note": "Elastic node comms"},
    {"port": 27017, "service": "MongoDB",       "risk": "CRITICAL", "note": "No-auth default exposure"},
    {"port": 27018, "service": "MongoDB-Shard", "risk": "HIGH",     "note": "Shard — often unauth"},
    {"port": 5984,  "service": "CouchDB",       "risk": "CRITICAL", "note": "Admin party — no creds"},
    {"port": 7474,  "service": "Neo4j",         "risk": "HIGH",     "note": "Default creds neo4j/neo4j"},
    {"port": 8086,  "service": "InfluxDB",      "risk": "HIGH",     "note": "Time-series — often no-auth"},
    # Cache/Brokers
    {"port": 5672,  "service": "RabbitMQ",      "risk": "HIGH",     "note": "Default guest/guest creds"},
    {"port": 9042,  "service": "Cassandra",     "risk": "HIGH",     "note": "CQL unauth access"},
    {"port": 9092,  "service": "Kafka",         "risk": "HIGH",     "note": "Unauth message intercept"},
    {"port": 11211, "service": "Memcached",     "risk": "HIGH",     "note": "Amplification / data leak"},
    {"port": 15672, "service": "RabbitMQ-Web",  "risk": "HIGH",     "note": "Management UI default creds"},
    {"port": 2181,  "service": "Zookeeper",     "risk": "HIGH",     "note": "Kafka cluster takeover"},
    # VNC
    {"port": 5900,  "service": "VNC",           "risk": "CRITICAL", "note": "No auth / weak password"},
    {"port": 5901,  "service": "VNC-1",         "risk": "CRITICAL", "note": "VNC display :1"},
    {"port": 5902,  "service": "VNC-2",         "risk": "HIGH",     "note": "VNC display :2"},
    # File sharing
    {"port": 69,    "service": "TFTP",          "risk": "HIGH",     "note": "Unauth file read/write"},
    {"port": 873,   "service": "Rsync",         "risk": "HIGH",     "note": "Unauth file exfil"},
    {"port": 548,   "service": "AFP",           "risk": "MEDIUM",   "note": "Apple file sharing"},
    {"port": 2049,  "service": "NFS",           "risk": "HIGH",     "note": "Mount without auth"},
    # Docker/K8s
    {"port": 2375,  "service": "Docker",        "risk": "CRITICAL", "note": "Unauth daemon — full host RCE"},
    {"port": 2376,  "service": "Docker-TLS",    "risk": "HIGH",     "note": "Check cert validation"},
    {"port": 2379,  "service": "etcd",          "risk": "CRITICAL", "note": "K8s secrets/tokens exposed"},
    {"port": 2380,  "service": "etcd-peer",     "risk": "HIGH",     "note": "etcd peer comms"},
    {"port": 8001,  "service": "K8s-API",       "risk": "CRITICAL", "note": "Kubernetes API proxy"},
    {"port": 10250, "service": "Kubelet",       "risk": "CRITICAL", "note": "Kubelet unauth — exec in pods"},
    {"port": 10255, "service": "Kubelet-RO",    "risk": "HIGH",     "note": "Kubelet read-only info leak"},
    # SNMP
    {"port": 161,   "service": "SNMP",          "risk": "HIGH",     "note": "Community string leak"},
    {"port": 162,   "service": "SNMP-Trap",     "risk": "MEDIUM",   "note": "SNMP trap receiver"},
    # Proxy
    {"port": 3128,  "service": "Squid",         "risk": "MEDIUM",   "note": "Open proxy"},
    {"port": 8118,  "service": "Privoxy",       "risk": "MEDIUM",   "note": "Open proxy"},
    # ICS/SCADA
    {"port": 102,   "service": "Siemens-S7",    "risk": "CRITICAL", "note": "S7 PLC — Stuxnet vector"},
    {"port": 502,   "service": "Modbus",        "risk": "CRITICAL", "note": "ICS no-auth by design"},
    {"port": 623,   "service": "IPMI",          "risk": "CRITICAL", "note": "Cipher0 bypass / RAKP hash"},
    {"port": 47808, "service": "BACnet",        "risk": "HIGH",     "note": "Building automation no-auth"},
    # Misc
    {"port": 4444,  "service": "Metasploit",    "risk": "CRITICAL", "note": "Default handler — backdoor indicator"},
    {"port": 4786,  "service": "Cisco-Smart",   "risk": "CRITICAL", "note": "Cisco Smart Install — unauth RCE"},
    {"port": 6667,  "service": "IRC",           "risk": "HIGH",     "note": "Botnet C2 channel"},
    {"port": 9050,  "service": "Tor",           "risk": "MEDIUM",   "note": "Tor SOCKS proxy"},
]

# Deduplicate
_seen = set()
UNIQUE_VULN_PORTS = []
for p in VULN_PORTS:
    if p["port"] not in _seen:
        _seen.add(p["port"])
        UNIQUE_VULN_PORTS.append(p)

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def get_port_info(port_num):
    for p in UNIQUE_VULN_PORTS:
        if p["port"] == port_num:
            return p
    return {"port": port_num, "service": "Unknown", "risk": "LOW", "note": ""}

def get_all_ports():
    return [p["port"] for p in UNIQUE_VULN_PORTS]

def port_string():
    """Return comma-separated port list for nmap."""
    return ",".join(str(p["port"]) for p in UNIQUE_VULN_PORTS)
