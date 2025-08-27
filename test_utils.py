import unittest
from utils import parse_config

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
