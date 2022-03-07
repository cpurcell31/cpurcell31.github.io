
number = 1
res = b''
while True:
    with open(str(number), "rb") as f:
        f.seek(0, 0)
        res += f.read(1)
    if number >= 4464:
        break
    number += 1
print(res)
