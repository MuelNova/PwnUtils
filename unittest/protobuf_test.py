import unittest
from pwnutils.protocol.protobuf import serialize

class TestProtobuf(unittest.TestCase):
    def test_serialize(self):
        obj = {
            'id': 123,
            'name': 'Alice',
            'is_passed': True
        }
        expected = b'\x08{\x12\x05Alice\x18\x01'
        self.assertEqual(serialize(obj), expected)

        # Test case 2: Mapping with integer keys
        obj = {
            2: 'Alice',
            1: 123,
            4: True
        }
        expected = b'\x08{\x12\x05Alice \x01'
        self.assertEqual(serialize(obj), expected)

        # Test case 3: List
        obj = [123, 'Alice', None, True]
        expected = b'\x08{\x12\x05Alice \x01'
        self.assertEqual(serialize(obj), expected)

if __name__ == '__main__':
    unittest.main()