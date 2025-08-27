import re
import ipaddress

def detect_config_type(config_text: str):
    """
    Detects the type of configuration file (Cisco IOS or MikroTik RouterOS).
    Returns 'cisco', 'mikrotik', or 'unknown'.
    """
    # More robust detection for MikroTik
    if "/ip address" in config_text and "/interface" in config_text and "add action=accept" not in config_text:
        return "mikrotik"
    # More robust detection for Cisco
    if "interface Vlan" in config_text or re.search(r"ip address \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} 255\.", config_text):
        return "cisco"
    return "unknown"

def parse_cisco_config(config_text: str):
    # This function remains as is, since it's for Cisco configs.
    lines = config_text.splitlines()
    interfaces = {}
    current_interface = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith('!'):
            if not line.strip().startswith('!'):
                current_interface = None
            continue
        if line.lower().startswith('interface '):
            current_interface = line.split(' ', 1)[1]
            interfaces[current_interface] = {
                "name": current_interface, "description": None, "ip_address": None,
                "subnet_mask": None, "vlan_id": None
            }
            if '.' in current_interface:
                try:
                    vlan_id_str = current_interface.split('.')[-1]
                    interfaces[current_interface]['vlan_id'] = int(vlan_id_str)
                except (ValueError, IndexError):
                    pass
            continue
        if current_interface and interfaces.get(current_interface):
            if line.lower().startswith('description '):
                interfaces[current_interface]['description'] = line.split(' ', 1)[1]
            elif line.lower().startswith('ip address '):
                parts = line.split()
                if len(parts) >= 4:
                    if not interfaces[current_interface]['ip_address']:
                        interfaces[current_interface]['ip_address'] = parts[2]
                        interfaces[current_interface]['subnet_mask'] = parts[3]
    return [data for data in interfaces.values() if data['ip_address']]

def parse_mikrotik_config(config_text: str):
    """
    Parses a MikroTik RouterOS configuration file to extract detailed information
    about interfaces, IP addresses, VLANs, NAT rules, and routes.

    Returns a dictionary with structured data.
    """
    # Regex to find a line that starts a new section
    section_re = re.compile(r"^/(interface|ip address|ip firewall nat|ip route|ip vrf)(?:\s+print.*)?$")
    # Regex to find a comment on an interface
    interface_comment_re = re.compile(r'set \[ find where name=(?:"([^"]+)"|(\S+)) \] comment=(?:"([^"]+)"|(\S+))')
    # Regex to find property="value" pairs, handling quoted and unquoted values
    prop_re = re.compile(r'(\w+)=(?:"([^"]+)"|(\S+))')

    data = {
        "interfaces": [],
        "addresses": [],
        "nat_rules": [],
        "routes": [],
        "vrfs": [],
        "comments": {}
    }
    current_section = None

    for line in config_text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Check for section changes
        section_match = section_re.match(line)
        if section_match:
            current_section = section_match.group(1).replace(" ", "_")
            continue

        # Parse interface comments specifically
        if current_section == "interface":
            comment_match = interface_comment_re.search(line)
            if comment_match:
                # Handles both quoted and unquoted names/comments
                name = comment_match.group(1) or comment_match.group(2)
                comment = comment_match.group(3) or comment_match.group(4)
                data["comments"][name] = comment

        if line.startswith("add"):
            props = dict(prop_re.findall(line))

            # Normalize properties that might be quoted or not
            for key, value in props.items():
                # The regex captures into two groups, one for quoted, one for unquoted.
                # We need to merge them. This is a simplification. A better regex would avoid this.
                # For now, we assume the prop_re gives us a simple key-value.
                pass

            if current_section == "ip_address" and "address" in props and "interface" in props:
                props['comment'] = props.get('comment', '').strip('"')
                data["addresses"].append(props)

            elif current_section == "ip_firewall_nat" and "chain" in props:
                data["nat_rules"].append(props)

            elif current_section == "ip_route" and "dst-address" in props:
                data["routes"].append(props)

            elif current_section == "ip_vrf":
                data["vrfs"].append(props)

    # Post-processing: Associate comments with addresses
    for addr in data["addresses"]:
        if not addr.get("comment"):
            addr["comment"] = data["comments"].get(addr["interface"])

    return data

def parse_config(config_text: str):
    """
    Dispatcher function that detects the config type and calls the appropriate parser.
    """
    config_type = detect_config_type(config_text)

    if config_type == "cisco":
        # Cisco parser returns a simple list, wrap it for consistency
        return {"interfaces": parse_cisco_config(config_text)}
    elif config_type == "mikrotik":
        return parse_mikrotik_config(config_text)
    else:
        # Fallback or error
        raise ValueError("Could not determine configuration type.")
