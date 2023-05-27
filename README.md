# PwnUtils
A collection of useful pwn scripts in one.

## Why
很多比赛中用到的东西都是重复且复杂的，将这些整合为一个方便的工具箱。


## Installation
还没写呢


## Usage
### utils
#### utils.encoding
##### to_varint
```python
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
```
将 bytes 或 int 转换为 varint 类型，并可指定返回 `bytes` 或是 `list[int]` 类型

### protocol
#### protocol.protobuf
##### serialize
```python
def serialize(obj: Mapping[str | int, Any] | list[Any]) -> bytes:
    """
    Serialize a protobuf object.
    :param obj: The object to serialize.
    :return: Serialized bytes.

    Examples:
     obj = {
            'id': 123,
            'name': 'Alice',
            'is_passed': True
        }

    obj = [123, 'Alice', None, True]

    obj = {
            1: 123,
            2: 'Alice',
            4: True
        }

    """
```
生成 Protobuf 序列化字节，目前支持 `int`, `str`, `bool` 以及 `None`，具体可看例子

## Examples