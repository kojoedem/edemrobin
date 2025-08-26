import unittest
from utils import parse_mikrotik_config

class TestMikroTikParseConfig(unittest.TestCase):

    def test_full_mikrotik_config(self):
        config = """
/interface vlan
add name=vlan100 vlan-id=100 interface=ether1
add name=vlan200 vlan-id=200 interface=ether1
/ip address
add address=192.168.100.1/24 interface=vlan100 comment="VLAN100"
add address=192.168.200.1/24 interface=vlan200 comment="VLAN200"
        """
        interfaces = parse_mikrotik_config(config)
        self.assertEqual(len(interfaces), 2)

        iface1 = interfaces[0]
        self.assertEqual(iface1['name'], 'vlan100')
        self.assertEqual(iface1['description'], 'VLAN100')
        self.assertEqual(iface1['ip_address'], '192.168.100.1')
        self.assertEqual(iface1['subnet_mask'], '255.255.255.0')
        self.assertEqual(iface1['vlan_id'], 100)

        iface2 = interfaces[1]
        self.assertEqual(iface2['name'], 'vlan200')
        self.assertEqual(iface2['description'], 'VLAN200')
        self.assertEqual(iface2['ip_address'], '192.168.200.1')
        self.assertEqual(iface2['vlan_id'], 200)

    def test_empty_config(self):
        config = ""
        interfaces = parse_mikrotik_config(config)
        self.assertEqual(len(interfaces), 0)

    def test_config_with_no_relevant_lines(self):
        config = "/system identity set name=Router\\n/system clock set time-zone-name=UTC"
        interfaces = parse_mikrotik_config(config)
        self.assertEqual(len(interfaces), 0)

if __name__ == '__main__':
    unittest.main()
