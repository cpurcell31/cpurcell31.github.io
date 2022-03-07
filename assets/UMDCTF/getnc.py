from pwn import *
import json

def get_n_c_loop():
    n_list = list()
    c_list = list()
    while True:
        x = r.recvuntil(b"Want another one? (y/n) ")
        r.sendline(b'y')
        res = r.recvuntil(b'}').decode().replace('\'', '\"')
        print("xd")
        res_l = json.loads(res)
        if res_l["e"] == 23:
            n_list.append(res_l["n"])
            c_list.append(res_l["c"])
        if len(n_list) == 23:
            return n_list, c_list


r = remote("0.cloud.chals.io", 30279)

r.recvuntil(b"Eddy Snowden setup a beacon constantly transmitting an encyrypted secret message, but he is always changing the public key for some reason. We've rigged up this intermediary to give you access to his encrypted transmissions. Would you like to capture a transmission? (y/n) ")
r.sendline(b'y')
res = r.recvuntil(b'}').decode().replace('\'', '\"')
res_l = json.loads(res)
print(res_l["e"])

n_list, c_list = get_n_c_loop()
with open("n_list.txt", "w") as f:
    for n in n_list:
        f.write(str(n) + "\n")

with open("c_list.txt", "w") as f:
    for c in c_list:
        f.write(str(c) + "\n")


