import unittest
from pwnutils.utils.encoding import to_varint


class TestEncoding(unittest.TestCase):
    def test_to_varint(self):
        self.assertEqual(to_varint(300), b'\xAC\x02')
        self.assertEqual(to_varint(127), b'\x7F')
        self.assertEqual(to_varint(0), b'\x00')
        self.assertEqual(to_varint(1), b'\x01')
        self.assertEqual(to_varint(128), b'\x80\x01')
        self.assertEqual(to_varint(16384), b'\x80\x80\x01')

        self.assertEqual(to_varint(300, to_bytes=False), [172, 2])
        self.assertEqual(to_varint(127, to_bytes=False), [127])
        self.assertEqual(to_varint(0, to_bytes=False), [0])
        self.assertEqual(to_varint(1, to_bytes=False), [1])
        self.assertEqual(to_varint(128, to_bytes=False), [128, 1])
        self.assertEqual(to_varint(16384, to_bytes=False), [128, 128, 1])