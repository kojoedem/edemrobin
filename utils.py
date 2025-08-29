import re
import ipaddress

def detect_config_type(config_text: str):
    """
    Detects the type of configuration file (Cisco IOS or MikroTik RouterOS).
    Returns 'cisco', 'mikrotik', or 'unknown'.
    """
    if not config_text.strip():
        return "unknown"

    # MikroTik markers
    mikrotik_pattern = r"^\s*/\w+"
    if re.search(mikrotik_pattern, config_text, re.MULTILINE):
        return "mikrotik"

    # Cisco markers
    cisco_pattern = r"^\s*interface \w+"
    if re.search(cisco_pattern, config_text, re.MULTILINE):
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
    Handles multi-line commands and properties with hyphens.

    Returns a dictionary with structured data.
    """
    # Regex to find property="value" or property=value pairs. Handles hyphens in keys.
    prop_re = re.compile(r'([\w-]+)=(?:"([^"]*)"|([^ ]+))')

    data = {
        "vlans": [], "addresses": [], "nat_rules": [], "pools": [], "dhcp_servers": [],
        "routes": [], "vrfs": [], "comments": {}
    }
    current_section = None
    has_content = False

    # Pre-process to handle multi-line commands ending with '\'
    processed_lines = []
    buffer = ""
    for line in config_text.splitlines():
        stripped_line = line.strip()
        if not stripped_line:
            continue
        if stripped_line.endswith('\\'):
            buffer += stripped_line[:-1].strip() + " "
        else:
            buffer += stripped_line
            processed_lines.append(buffer)
            buffer = ""
    if buffer:
        processed_lines.append(buffer)

    for line in processed_lines:
        if not line or line.startswith('#'):
            continue

        if line.startswith('/'):
            # Handles sections like /ip address, /ip firewall nat, etc.
            # Also handles deeper sections like /ip dhcp-server network
            current_section = ' '.join(line.split('/')[1:]).strip()
            continue

        if line.startswith("add"):
            has_content = True
            # Correctly parse properties from the part of the string after "add"
            prop_string = line[3:].strip()
            matches = prop_re.findall(prop_string)
            props = {key: val_quoted or val_unquoted for key, val_quoted, val_unquoted in matches}

            if current_section == "interface vlan":
                data["vlans"].append(props)
            elif current_section == "ip address":
                data["addresses"].append(props)
            elif current_section == "ip firewall nat":
                data["nat_rules"].append(props)
            elif current_section == "ip pool":
                data["pools"].append(props)
            elif current_section == "ip dhcp-server":
                data["dhcp_servers"].append(props)
            elif current_section == "ip route":
                data["routes"].append(props)
            elif current_section == "ip vrf":
                data["vrfs"].append(props)


    if not has_content:
        return None

    return data

def parse_config(config_text: str):
    """
    Dispatcher function that detects the config type and calls the appropriate parser.
    """
    config_type = detect_config_type(config_text)

    if config_type == "cisco":
        return parse_cisco_config(config_text)
    elif config_type == "mikrotik":
        # The mikrotik parser returns a dictionary, we might need to adapt
        # depending on what the caller expects. For now, let's assume
        # the tests will be adapted to handle the dictionary format.
        parsed_data = parse_mikrotik_config(config_text)
        return parsed_data['addresses'] if parsed_data else []
    else:
        # Return empty list for unknown or empty configs
        return []
