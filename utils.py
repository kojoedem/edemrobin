import ipaddress
import re

def parse_config(config_text: str):
    """
    Extract IPs & group into blocks from Cisco-style config.
    Returns a tuple of:
    - a list of dictionaries, each representing an IP block with usage stats.
    - a list of IPs found in the config.
    - a list of malformed/invalid IP entries found.
    """
    # Matches: ip address 192.168.1.1 255.255.255.0.
    # Allows almost any non-whitespace characters for IP and mask,
    # so we can catch and report invalid formats.
    ip_matches = re.findall(r"ip address ([^\s]+) ([^\s]+)", config_text)

    ip_blocks = {}
    used_ips = []
    invalid_entries = []

    for ip_str, mask_str in ip_matches:
        try:
            # The ipaddress module is strict and will raise ValueError on invalid input.
            network = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)

            # Use the network's CIDR string as the key
            block_cidr = network.with_prefixlen

            if block_cidr not in ip_blocks:
                ip_blocks[block_cidr] = {
                    "used_ips": set(),
                    "total_count": network.num_addresses,
                }

            # The IP address from the config line is a used IP.
            ip_blocks[block_cidr]["used_ips"].add(ip_str)
            used_ips.append(ip_str)

        except ValueError:
            # Catches invalid IPs (e.g., 192.168,.1.0) or invalid masks.
            invalid_entries.append(f"ip address {ip_str} {mask_str}")
            continue

    # Convert the dictionary of blocks into a list of dictionaries with more stats
    processed_blocks = []
    for cidr, block_data in ip_blocks.items():
        used_count = len(block_data["used_ips"])
        total_count = block_data["total_count"]
        available_count = total_count - used_count

        processed_blocks.append({
            "block_cidr": cidr,
            "used_ips": sorted(list(block_data["used_ips"])),
            "used_count": used_count,
            "total_count": total_count,
            "available_count": available_count,
        })

    # Sort blocks for consistent output
    if processed_blocks:
        processed_blocks.sort(key=lambda x: ipaddress.ip_network(x['block_cidr']))

    return processed_blocks, used_ips, invalid_entries
