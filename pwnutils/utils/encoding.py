import struct
from typing import Literal, overload


@overload
def to_varint(value: bytes | int,
              to_bytes: Literal[True] = True,
              *,
              endian: Literal['big', 'little'] = 'little'
              ) -> bytes:
    ...
@overload
def to_varint(value: bytes | int,
              to_bytes: Literal[False] = False,
              *,
              endian: Literal['big', 'little'] = 'little'
              ) -> list[int]:
    ...


def to_varint(value: bytes | int,
              to_bytes: bool = True,
              *,
              endian: Literal['big', 'little'] = 'little'
              ) -> list[int] | bytes:
    """
    Convert an integer to a varint.
    :param value: The integer to convert.
    :param to_bytes: Whether to return a bytes object or a list of integers.
    :param endian: The endianness of the bytes object.
    :return: The varint.
    """
    if isinstance(value, bytes):
        value = int.from_bytes(value, endian)
    if value == 0:
        return b'\x00' if to_bytes else [0]
    res = []
    while value:
        if (value >> 7) != 0:
            res.append(0x80 | (value & 0x7F))
            value = value >> 7
        else:
            res.append(value & 0x7F)
            break
    if to_bytes:
        return b"".join(struct.pack('B', i) for i in res)
    return res