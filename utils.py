import ipaddress


def parse_config(config_text: str):
    """
    Extract IPs & group into blocks from Cisco-style config.
    """
    # Matches: ip address 192.168.1.1 255.255.255.0
    ip_matches = re.findall(r"ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)", config_text)

    ip_blocks = {}
    used_ips = []

    for ip, mask in ip_matches:
        try:
            network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            if str(network) not in ip_blocks:
                ip_blocks[str(network)] = []
            ip_blocks[str(network)].append(ip)
            used_ips.append(ip)
        except Exception:
            continue

    return ip_blocks, used_ips
