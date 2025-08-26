import ipaddress
import re

def parse_config(config_text: str):
    """
    Parses a Cisco-style configuration line by line to extract detailed
    interface information, including sub-interface VLANs and descriptions.

    Returns a list of dictionaries, where each dictionary represents an
    interface with an IP address.
    """
    lines = config_text.splitlines()
    interfaces = {}
    current_interface = None

    for line in lines:
        # Normalize the line
        line = line.strip()

        # Reset context if line is empty or a comment
        if not line or line.startswith('!'):
            if not line.strip().startswith('!'): # Don't reset context on comments within an interface block
                current_interface = None
            continue

        # Detect the start of a new interface block
        if line.lower().startswith('interface '):
            current_interface = line.split(' ', 1)[1]
            interfaces[current_interface] = {
                "name": current_interface,
                "description": None,
                "ip_address": None,
                "subnet_mask": None,
                "vlan_id": None
            }
            # Try to parse VLAN ID from sub-interface name (e.g., Gig0/0.500)
            if '.' in current_interface:
                try:
                    vlan_id_str = current_interface.split('.')[-1]
                    interfaces[current_interface]['vlan_id'] = int(vlan_id_str)
                except (ValueError, IndexError):
                    pass  # Not a valid VLAN sub-interface
            continue

        # If we are inside an interface block, parse its attributes
        if current_interface and interfaces.get(current_interface):
            # Parse description
            if line.lower().startswith('description '):
                # Get everything after "description "
                interfaces[current_interface]['description'] = line.split(' ', 1)[1]

            # Parse IP address
            elif line.lower().startswith('ip address '):
                parts = line.split()
                # Expecting "ip address <ip> <netmask>"
                if len(parts) >= 4:
                    # This will capture the primary IP. A more complex parser could handle secondary IPs.
                    if not interfaces[current_interface]['ip_address']:
                        interfaces[current_interface]['ip_address'] = parts[2]
                        interfaces[current_interface]['subnet_mask'] = parts[3]

    # Filter out interfaces that did not have an IP address
    # and return a clean list of dictionaries.
    results = [data for data in interfaces.values() if data['ip_address']]

    return results
