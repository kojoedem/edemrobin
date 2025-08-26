import unittest
from utils import parse_config

class TestParseConfig(unittest.TestCase):

    def test_simple_valid_config(self):
        config = """
        interface Vlan10
         ip address 192.168.10.1 255.255.255.0
        !
        interface Vlan20
         ip address 192.168.20.1 255.255.255.0
        """
        processed_blocks, used_ips, invalid_entries = parse_config(config)

        self.assertEqual(len(processed_blocks), 2)
        self.assertEqual(len(used_ips), 2)
        self.assertEqual(len(invalid_entries), 0)

        self.assertEqual(processed_blocks[0]['block_cidr'], '192.168.10.0/24')
        self.assertEqual(processed_blocks[0]['used_count'], 1)
        self.assertEqual(processed_blocks[0]['total_count'], 256)
        self.assertEqual(processed_blocks[0]['available_count'], 255)
        self.assertIn('192.168.10.1', processed_blocks[0]['used_ips'])

        self.assertEqual(processed_blocks[1]['block_cidr'], '192.168.20.0/24')
        self.assertEqual(processed_blocks[1]['used_count'], 1)
        self.assertEqual(processed_blocks[1]['total_count'], 256)
        self.assertEqual(processed_blocks[1]['available_count'], 255)
        self.assertIn('192.168.20.1', processed_blocks[1]['used_ips'])

    def test_config_with_invalid_entries(self):
        config = """
        interface Vlan10
         ip address 192.168,10.1 255.255.255.0
        !
        interface Vlan20
         ip address 10.0.0.1 255.255.255.256
        !
        interface Vlan30
         ip address 172.16.0.1 255.255.255.0
        """
        processed_blocks, used_ips, invalid_entries = parse_config(config)

        self.assertEqual(len(processed_blocks), 1)
        self.assertEqual(len(used_ips), 1)
        self.assertEqual(len(invalid_entries), 2)

        self.assertEqual(processed_blocks[0]['block_cidr'], '172.16.0.0/24')
        self.assertIn('172.16.0.1', used_ips)

        self.assertIn('ip address 192.168,10.1 255.255.255.0', invalid_entries)
        self.assertIn('ip address 10.0.0.1 255.255.255.256', invalid_entries)

    def test_empty_config(self):
        config = ""
        processed_blocks, used_ips, invalid_entries = parse_config(config)
        self.assertEqual(len(processed_blocks), 0)
        self.assertEqual(len(used_ips), 0)
        self.assertEqual(len(invalid_entries), 0)

    def test_config_with_multiple_ips_in_same_block(self):
        config = """
        interface Vlan10
         ip address 192.168.10.1 255.255.255.0
         ip address 192.168.10.2 255.255.255.0
        """
        processed_blocks, used_ips, invalid_entries = parse_config(config)

        self.assertEqual(len(processed_blocks), 1)
        self.assertEqual(len(used_ips), 2)
        self.assertEqual(len(invalid_entries), 0)

        self.assertEqual(processed_blocks[0]['block_cidr'], '192.168.10.0/24')
        self.assertEqual(processed_blocks[0]['used_count'], 2)
        self.assertEqual(processed_blocks[0]['available_count'], 254)
        self.assertIn('192.168.10.1', processed_blocks[0]['used_ips'])
        self.assertIn('192.168.10.2', processed_blocks[0]['used_ips'])

if __name__ == '__main__':
    unittest.main()
