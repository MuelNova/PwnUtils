from typing import Mapping, Any

from pwnutils.utils.encoding import to_varint

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
    if isinstance(obj, Mapping):
        keys = obj.keys()
        if all(isinstance(key, int) for key in keys):
            runner = sorted(obj.items())
        else:
            runner = enumerate(obj.values(), start=1)
    elif isinstance(obj, list):
        runner = enumerate(obj, start=1)
    else:
        raise ValueError(f"Unsupported type: {type(obj)}")
    
    message = b''
    for key, value in runner:
        field_number = key << 3
        if isinstance(value, int):
            message += to_varint(field_number | 0) + to_varint(value)
        elif isinstance(value, (str, bytes)):
            if isinstance(value, str):
                value = value.encode()
            message += to_varint(field_number | 2) + to_varint(len(value)) + value
        elif isinstance(value, bool):
            message += to_varint(field_number | 0) + b'\x01' if value else b'\x00'
        elif value is None:
            continue
        else:
            raise ValueError(f"Unsupported type {type(value)} of value {value}")
    return message
