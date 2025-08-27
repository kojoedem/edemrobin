import ipaddress
import re

def detect_config_type(config_text: str):
    """
    Detects the type of configuration file (Cisco IOS or MikroTik RouterOS).
    Returns 'cisco', 'mikrotik', or 'unknown'.
    """
    if "/ip address add" in config_text or "/interface bridge add" in config_text:
        return "mikrotik"
    if "interface Vlan" in config_text or ("ip address" in config_text and "255." in config_text):
        return "cisco"
    return "unknown"

def parse_cisco_config(config_text: str):
    """
    Parses a Cisco-style configuration line by line to extract detailed
    interface information, including sub-interface VLANs and descriptions.
    """
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
                "name": current_interface,
                "description": None,
                "ip_address": None,
                "subnet_mask": None,
                "vlan_id": None
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
    Parses a MikroTik-style configuration to extract detailed
    interface and IP address information.
    """
    vlans = {}
    ip_entries = []
    current_section = None

    vlan_regex = re.compile(r'add name=(?P<name>\S+).*vlan-id=(?P<vlan_id>\d+)')
    ip_regex = re.compile(r'add address=(?P<address>\S+)\s+interface=(?P<interface>\S+)(?:\s+comment="(?P<comment>[^"]+)")?')

    for line in config_text.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith('/'):
            if '/interface vlan' in line:
                current_section = 'vlan'
            elif '/ip address' in line:
                current_section = 'ip_address'
            else:
                current_section = None
            continue

        if current_section == 'vlan' and line.startswith('add'):
            match = vlan_regex.search(line)
            if match:
                data = match.groupdict()
                vlans[data['name']] = int(data['vlan_id'])

        elif current_section == 'ip_address' and line.startswith('add'):
            match = ip_regex.search(line)
            if match:
                ip_entries.append(match.groupdict())

    # Combine the parsed data
    interfaces = []
    for entry in ip_entries:
        try:
            ip_interface = ipaddress.ip_interface(entry['address'])
            interfaces.append({
                "name": entry['interface'],
                "description": entry.get('comment'),
                "ip_address": str(ip_interface.ip),
                "subnet_mask": str(ip_interface.netmask),
                "vlan_id": vlans.get(entry['interface'])
            })
        except ValueError:
            continue

    return interfaces

def parse_config(config_text: str):
    """
    Dispatcher function that detects the config type and calls the appropriate parser.
    """
    config_type = detect_config_type(config_text)

    if config_type == "cisco":
        return parse_cisco_config(config_text)
    elif config_type == "mikrotik":
        return parse_mikrotik_config(config_text)
    else:
        print("WARNING: Could not determine config type. Falling back to Cisco parser.")
        return parse_cisco_config(config_text)
