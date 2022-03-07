import hashlib
from base64 import b64encode
from random import randint
from pwn import *


rand = b64encode(b"BxH9Kxi55LmT")
header = "1:20:220304:gary@hashcash.com::{}:".format(rand.decode()).encode()
print(header)


counter = randint(0, 125236346436)
result = ''
while True:
    h1 = header + b64encode(str(counter).encode())
    m = hashlib.new("sha1", h1)
    hashed = m.digest()
    print(hashed)
    if hashed[:2] == b'\x00\x00' and hashed[2] <= 15:
        result = h1
        break
    counter += 1

print(h1)

r = remote("0.cloud.chals.io", 17015)
r.recvuntil(b"Would you like to send an email (y/n)?")
r.sendline(b'y')
r.recvuntil(b'X-Hashcash: ')
r.sendline(result)
r.interactive()
