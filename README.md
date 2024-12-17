# Libc-GOT-Hijacking 

Important: You can only use this skill for glibcs < 2.39.

Transform arbitrary write to RCE.

This is a userspace attacking skill: If you can write arbitrary memory space, you can use this method to execute arbitrary code. 

> You only need to know the base address of Glibc
> Glibc is FULL RELRO by default for glibc2.39. A great security improvement! We can't hijack Libc GOT on libc version >= 2.39

# Update (Dec 17th., 2024)

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

I'll provide a demo later. A simple way to get a shell is just to modify `del/new` got to `system` and `cin` the string `/bin/sh` (Kylebot told me people already found it even though they didn't show that publicly I just re-find this technique). But if GOT is what we want, aha, we can do libc-got-hijacking! 

## glibc > 2.35 & glibc <=2.38

Compared to glibc<=2.35 there is mitigation implemented, which forbids the methods for the old library. However, we designed a method to bypass it and execute arbitrary code by 
once arbitrary write on Glibc's GOT table. This method performs Return Oriented Programming (ROP) attack on the Global Offset Table (GOT). 

![AttackFlow](./Img/AttackFlow.png)


You can find details, templates, demos, and everything you want in: [Details][0] and [Templates][3]


## glibc <= 2.35


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
