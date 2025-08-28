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
        data = parse_mikrotik_config(config)
        self.assertIsNotNone(data)
        self.assertEqual(len(data['addresses']), 2)

        addr1 = data['addresses'][0]
        self.assertEqual(addr1['address'], '192.168.100.1/24')
        self.assertEqual(addr1['interface'], 'vlan100')
        self.assertEqual(addr1['comment'], 'VLAN100')

        addr2 = data['addresses'][1]
        self.assertEqual(addr2['address'], '192.168.200.1/24')
        self.assertEqual(addr2['interface'], 'vlan200')
        self.assertEqual(addr2['comment'], 'VLAN200')

    def test_empty_config(self):
        config = ""
        data = parse_mikrotik_config(config)
        self.assertIsNone(data)

    def test_config_with_no_relevant_lines(self):
        config = "/system identity set name=Router\\n/system clock set time-zone-name=UTC"
        data = parse_mikrotik_config(config)
        self.assertIsNone(data)

if __name__ == '__main__':
    unittest.main()
