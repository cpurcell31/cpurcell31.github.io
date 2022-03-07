import sys
import binascii
from Crypto.PublicKey import RSA
from base64 import b64decode
from functools import reduce

if (len(sys.argv)<3):
    print("\t\n\nArg error: python rsaHastad.py <n0 File> <n1 File> <n2 File> <c0 File> <c1 File> <c2 File> [--decimal/--hex/--b64] [-v/--verbose]\n\n")
    exit()

print("\n")


def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
 
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod
 
 
def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a // b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

def find_invpow(x,n):
    high = 1
    while high ** n < x:
        high *= 2
    low = high//2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1


def parseN(argv,index):
    file = open(argv[index],'r')
    fileInput = ''.join(file.readlines()).strip()
    try:
        fileInput = long(fileInput)
        return fileInput
    except ValueError:
        from Crypto.PublicKey import RSA
        return long(RSA.importKey(fileInput).__getattr__('n'))
        pass



if __name__ == '__main__':
    e = 23
    cmd = ' '.join(sys.argv)
    if '-v' in cmd or '--verbose' in cmd:
        verbose = True
    else:
        verbose = False

    n_list = list()
    with open('n_list.txt', 'r') as f:
        lines = f.readlines()
        for line in lines:
            n_list.append(int(line.strip()))

    c_list = list()
    with open('c_list.txt', 'r') as f:
        lines = f.readlines()
        for line in lines:
            c_list.append(int(line.strip()))

    n = n_list
    a = c_list

    result = (chinese_remainder(n, a))
    resultHex = str(hex(find_invpow(result,23)))[2:-1]
    print("")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("Decoded Hex :\n",resultHex)
    print("---------------------------")
    print("As Ascii :\n",binascii.unhexlify(resultHex.encode()))
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
