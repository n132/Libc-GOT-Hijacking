# Libc-GOT-Hijacking 

Transform arbitrary write to RCE.
Libc makes it full RELRO at 2.39 so this skill doesn't work for glibc-2.39+.
However, it works for the libstdc++ on the latest Ubuntu LTS.

This is a userspace attacking skill: If you can write arbitrary memory space, you can use this method to execute arbitrary code. 

> You only need to know the base address of Glibc

The simplest way to attack is to find a function using writable GOT value and set it `system` to perform `system("/bin/sh")`. It depends on the challenges/cases and it's **good enough** for most cases and this repo is giving a more complex/verbose solution to gain not only RIP but ROP for generic cases.

# Before Reading

This repo is a generic solution to gain Code Execution (ROP level). 
- You don't need this repo **unless**
    - You just want a generic solution without spending time debugging a specific case
    - You need ROP instead of system("/bin/sh").
 
For most simple cases, the simple solution is:
- Hijack one got entry (<=6 bytes write)
- Find a trigger function for which the parameters are nice.
    - Case 1: The trigger function takes controllable parameters. (e.g., `some_func(str)`). We set `some_func`'s got to `system`.
    - Case 2: The trigger function takes stack pointers (in a retunable function stack frame) as the first parameter. -> We set it to `gets` to get a buffer overflow.

# Update 
- Dec 17th., 2024
While exploiting a CTF challenge, I found `libstdc++` is a juicy target of this technique. It's still usable on the latest LTS-ubuntu(24.04).

```sh
[14:26:12] n132 :: xps  ➜  ~/Downloads/FL_Support_Center » pwn checksec /lib/x86_64-linux-gnu/libstdc++.so.6
[*] '/lib/x86_64-linux-gnu/libstdc++.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

A simple way to get a shell is just to modify `fread/fwrite` got to `system` and `cin/cout` the string `/bin/sh`. But if ROP is what we want, we can do libc-got-hijacking (ROP over GOT) (even though it's unnecessary, it's a general solution!) 

Here is a demo (https://asciinema.org/a/krgiZ9HEX633nOhgT86OJy3aH)
```c
[18:34:04] n132 :: xps  ➜  ~/demo » cat ./rce.cpp && g++ ./rce.cpp -o ./rce && echo "id" | ./rce
#include <iostream>
int main(){
    // Hijack fwrite@got[plt] to system
    // cout gonna run arbitrary commands
    int num = 915;
    std::string str;
    size_t libc_base = (size_t)system-0x00058740;
    size_t * add_of_del_got = (size_t *)(libc_base + 0x277000 + 0x400000 + num*8);
    * add_of_del_got = (size_t )system;
    std::cin >> str;
    std::cout << str << std::endl;
}
uid=1000(n132) gid=1000(n132) groups=1000(n132),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),114(lpadmin),984(docker)
```

## glibc (2.36-2.38)

Compared to glibc<=2.35 there is mitigation implemented, which forbids the methods for the old library. However, we designed a method to bypass it and execute arbitrary code by 
once arbitrary write on Glibc's GOT table. This method performs Return Oriented Programming (ROP) attack on the Global Offset Table (GOT). 

![AttackFlow](./Img/AttackFlow.png)


You can find details, templates, demos, and everything you want in: [Details][0] and [Templates][3]


## glibc (unk-2.35)


I learned the original method from [Sammy Hajhamid][2] also the methods for glibc <=2.35 are inspired by his work.

Based on his work, We designed a method to execute arbitrary code by once arbitrary write on Glibc's GOT table. The method uses `PLT_0` to push `libc_exe_address` to the stack and then use `POP RSP, RET` to execute our `ROPchain`.

You can find details, templates, demos, and everything you want in: [Details][1] and [Templates][4]

# Acknowledgments

- Great job [@swing][5] on the impressive work with glibc >2.35!

- Appreciate the original work done by @pepsipu.

# Reference link
- [@pepsipu's Method][2]


[0]: ./Post/README.md
[1]: ./Pre/README.md
[2]: https://hackmd.io/@pepsipu/SyqPbk94a
[3]: ./Post/one_punch.py
[4]: ./Pre/templates.md
[5]: https://bestwing.me/
