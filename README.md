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

### gadgets
#### gadgets.orw
##### orw_rop
```python
def orw_rop(flag_addr: Optional[int] = 0,
            rdi: int = 0,
            rsi: int = 0,
            rdx: int = 0,
            rax: Optional[int] = 0,
            syscall: Optional[int] = 0,
            *,
            sig: Optional[SigreturnFrame] = None,
            rdx_r12: bool = False,
            open_at: bool = False,
            read_addr: Optional[int] = 0,
            write_addr: Optional[int] = 0,
            open_addr: Optional[int] = 0) -> bytes:
    """
    生成 ORW 的 ROP 链。仅适用于 64 位。
    :param flag_addr: '/flag' 的地址
    :param rdi: pop rdi; ret;
    :param rsi: pop rsi; ret;
    :param rdx: pop rdx; ret; 
                或 pop rdx; pop r12; ret; 此时将 rdx_r12 设置为 True
    :param rax: pop rax; ret;
    :param syscall: syscall; ret;
    :param sig: SigreturnFrame，可用于快捷布置 '/flag', 与 flag_addr 二选一
    :param rdx_r12: 使用的是 pop rdx; pop r12; ret; (或是其它 pop 两次的 gadget)
    :param open_at: 使用 openat 而非 open
    :param read_addr: read 的地址，与 (syscall, rax) 二选一
    :param write_addr: write 的地址，与 (syscall, rax) 二选一
    :param open_addr: open 的地址，与 (syscall, rax) 二选一
    :return: ROP 链
    """
```

##### orw_shellcode
```python
def orw_shellcode(ROP_addr: Optional[int] = 0,
                  rdi: int = 0,
                  rsi: int = 0,
                  rdx: int = 0,
                  rax: Optional[int] = 0,
                  syscall: Optional[int] = 0,
                  *,
                  mprotect_addr: Optional[int] = 0,
                  sig: Optional[SigreturnFrame] = None,
                  rdx_r12: bool = False,
                  sc_only: bool = False) -> bytes:
    """
    生成 ORW 的 shellcode。仅适用于 64 位，布置 mprotect rop + shellcode。
    :param ROP_addr: ROP 链的地址
    :param rdi: pop rdi; ret;
    :param rsi: pop rsi; ret;
    :param rdx: pop rdx; ret;
                或 pop rdx; pop r12; ret; 此时将 rdx_r12 设置为 True
    :param rax: pop rax; ret;
    :param syscall: syscall; ret;
    :param mprotect_addr: mprotect 的地址，与 (syscall, rax) 二选一
    :param sig: SigreturnFrame，可用于快捷布置 mprotect rop
    :param rdx_r12: 使用的是 pop rdx; pop r12; ret; (或是其它 pop 两次的 gadget)
    :param sc_only: 仅返回 shellcode
    :return: ROP 链 + shellcode
    """
```

#### gadgets.srop
##### FAST_HEAP_SROP
```python
def FAST_HEAP_SROP(chunk_content_addr: int,
                   setcontext_61: int,
                   read_addr: Optional[int] = 0,
                   *,
                   use_magic: bool = True,
                   is_free_chunk: bool = False,
                   free_chunk_func: Optional[int] = None,
                   write_addr: Optional[int] = 0,
                   syscall_addr: Optional[int] = 0,
                   **kwargs) -> SigreturnFrame:
    """
    一键生成 fast_read_srop + heap_srop 的组合，用于在堆上一键布置 READ 的 SROP
    :param chunk_content_addr: chunk 的内容指针
    :param setcontext_61: setcontext + 61
    :param read_addr: READ 函数的地址
    :param use_magic: 是否使用 magic gadget
    :param is_free_chunk: 是否是 __free_hook 对应的 chunk
    :param free_chunk_func: __free_hook 内容（在 is_free_chunk 为 True 时指定）
    :param write_addr: READ 到的地址
    :param syscall_addr: syscall 的地址(二者必须指定一个，优先使用 read_addr)
    :param kwargs: 传递给 fast_read_srop 生成的 SigreturnFrame 的参数
    :return: 生成好的 SigreturnFrame
    """
```

##### fast_read_srop
```python
def fast_read_srop(write_addr: int,
                   read_addr: Optional[int] = 0,
                   *,
                   syscall_addr: Optional[int] = 0) -> SigreturnFrame:
    """
    快速生成 READ 的 SROP，即 read(0, write_addr, 0x2000)

    :param write_addr: READ 到的地址
    :param read_addr: READ 函数的地址
    :param syscall_addr: syscall 的地址(二者必须指定一个，优先使用 read_addr)
    :return: 生成好的 SigreturnFrame
    """
```

##### heap_srop
```python
def heap_srop(sig: SigreturnFrame,
              chunk_content_addr: int,
              setcontext_61: int,
              *,
              use_magic: bool = True,
              is_free_chunk: bool = False,
              free_chunk_func: Optional[int] = None) -> SigreturnFrame:
    """
    创建一个 SigreturnFrame，用于在堆上布置 SROP。
    可以在 free chunk 上布置 SROP，也可以在非 free chunk 上布置 SROP。
    支持 magic gadget(2.31+) 和非 magic gadget(2.27)。
    - Magic gadget use case:
        - not free chunk:
            new(free_hook_idx, content=magic_gadget)  # __free_hook
            new(chunk_idx, content=heap_srop(...))
            free(chunk_idx)
        
        - free chunk:
            new(chunk_idx, content=heap_srop(..., is_free_chunk=True, free_chunk_func=magic_gadget))  # __free_hook
            free(__free_hook)

    - No magic gadget use case:
        - not free chunk:
            new(free_hook_idx, content=setcontext_61)  # __free_hook
            new(chunk_idx, content=heap_srop(..., use_magic=False))
            free(chunk_idx)
        - free chunk:
            new(chunk_idx, content=heap_srop(..., use_magic=False, is_free_chunk=True, free_chunk_func=setcontext_61))  # __free_hook
            free(__free_hook)

    :param sig: SigreturnFrame
    :param chunk_content_addr: chunk 的内容指针
    :param setcontext_61: setcontext + 61
    :param use_magic: 是否使用 magic gadget
    :param is_free_chunk: 是否是 __free_hook 对应的 chunk
    :param free_chunk_func: __free_hook 内容（在 is_free_chunk 为 True 时指定）
    :return: 生成好的 SigreturnFrame
    use_magic:    mov rdx, qword ptr [rdi+8];
                  mov [rsp], rax;
                  call qword ptr [rdx+0x20];
    """
```
## Examples