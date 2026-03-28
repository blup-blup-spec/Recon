# utils/cidr.py

import ipaddress


def expand_target(target: str) -> list:
    target = target.strip()
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            raise ValueError(f"Invalid CIDR: {e}")

    if "-" in target:
        parts = target.split("-")
        if len(parts) == 2:
            try:
                start = ipaddress.ip_address(parts[0].strip())
                end   = ipaddress.ip_address(parts[1].strip())
                ips = []
                cur = start
                while cur <= end:
                    ips.append(str(cur))
                    cur += 1
                return ips
            except ValueError:
                pass

    return [target]


def summarize_target(target: str) -> str:
    target = target.strip()
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return f"{target}  ({net.num_addresses - 2} hosts)"
        except ValueError:
            pass
    if "-" in target:
        return f"Range: {target}"
    return f"Host: {target}"
