import unittest
import ipaddress
from utils import parse_config, group_networks_by_supernet


class TestGroupNetworksBySupernet(unittest.TestCase):

    def test_basic_grouping(self):
        networks = [
            ipaddress.ip_network('192.168.1.0/28'),
            ipaddress.ip_network('192.168.1.16/28'),
            ipaddress.ip_network('192.168.2.0/26'),
            ipaddress.ip_network('10.0.0.0/8'),
        ]
        grouped = group_networks_by_supernet(networks, prefixlen=24)
        self.assertIn('192.168.1.0/24', grouped)
        self.assertEqual(len(grouped['192.168.1.0/24']), 2)
        self.assertIn('192.168.2.0/24', grouped)
        self.assertEqual(len(grouped['192.168.2.0/24']), 1)
        self.assertIn('10.0.0.0/8', grouped)
        self.assertEqual(len(grouped['10.0.0.0/8']), 1)

    def test_grouping_with_larger_prefix(self):
        networks = [
            ipaddress.ip_network('172.16.1.0/24'),
            ipaddress.ip_network('172.16.2.0/24'),
            ipaddress.ip_network('172.17.1.0/24'),
        ]
        grouped = group_networks_by_supernet(networks, prefixlen=16)
        self.assertIn('172.16.0.0/16', grouped)
        self.assertEqual(len(grouped['172.16.0.0/16']), 2)
        self.assertIn('172.17.0.0/16', grouped)
        self.assertEqual(len(grouped['172.17.0.0/16']), 1)

    def test_empty_input(self):
        grouped = group_networks_by_supernet([], prefixlen=24)
        self.assertEqual(grouped, {})

    def test_network_larger_than_prefix(self):
        networks = [ipaddress.ip_network('10.0.0.0/8')]
        grouped = group_networks_by_supernet(networks, prefixlen=24)
        self.assertIn('10.0.0.0/8', grouped)
        self.assertEqual(len(grouped['10.0.0.0/8']), 1)


class TestAdvancedParseConfig(unittest.TestCase):

    def test_simple_interface(self):
        config = """
        interface GigabitEthernet0/1
         description Main uplink
         ip address 192.168.1.1 255.255.255.0
        """
        interfaces = parse_config(config)
        self.assertEqual(len(interfaces), 1)
        iface = interfaces[0]
        self.assertEqual(iface['name'], 'GigabitEthernet0/1')
        self.assertEqual(iface['description'], 'Main uplink')
        self.assertEqual(iface['ip_address'], '192.168.1.1')
        self.assertEqual(iface['subnet_mask'], '255.255.255.0')
        self.assertIsNone(iface['vlan_id'])

    def test_sub_interface_with_vlan(self):
        config = """
        interface GigabitEthernet0/0.500
         description Servers VLAN
         ip address 10.10.50.1 255.255.255.0
        """
        interfaces = parse_config(config)
        self.assertEqual(len(interfaces), 1)
        iface = interfaces[0]
        self.assertEqual(iface['name'], 'GigabitEthernet0/0.500')
        self.assertEqual(iface['description'], 'Servers VLAN')
        self.assertEqual(iface['ip_address'], '10.10.50.1')
        self.assertEqual(iface['vlan_id'], 500)

    def test_multiple_interfaces(self):
        config = """
        !
        interface Vlan10
         description Voice
         ip address 10.1.10.1 255.255.255.0
        !
        interface Vlan20
         description Data
         ip address 10.1.20.1 255.255.255.0
        !
        interface Dialer1
         no ip address
        """
        interfaces = parse_config(config)
        self.assertEqual(len(interfaces), 2)
        self.assertEqual(interfaces[0]['name'], 'Vlan10')
        self.assertEqual(interfaces[1]['name'], 'Vlan20')
        self.assertEqual(interfaces[1]['description'], 'Data')
        self.assertEqual(interfaces[0]['ip_address'], '10.1.10.1')

    def test_empty_config(self):
        config = ""
        interfaces = parse_config(config)
        self.assertEqual(len(interfaces), 0)

    def test_interface_with_no_ip(self):
        config = "interface Loopback0\\n description Management"
        interfaces = parse_config(config)
        self.assertEqual(len(interfaces), 0)

if __name__ == '__main__':
    unittest.main()
