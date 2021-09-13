import base64
from pwn import *
from Crypto.Util.number import long_to_bytes
from sympy import integer_nthroot


morse_dict = {'1':'.----', 
        '2':'..---', 
        '3':'...--',
        '4':'....-', 
        '5':'.....', 
        '6':'-....',
        '7':'--...', 
        '8':'---..', 
        '9':'----.',
        '0':'-----'}

def decrypt_morse(message):
    result = list()
    c = ''
    number = ''
    for letter in message:
        if letter != ' ' and letter != '/':
            i = 0
            c += letter
        else:
            i += 1
            if i == 2:
                result.append(int(number))
                number = ''
            else:
                number += list(morse_dict.keys())[list(morse_dict.values()).index(c)]
                c = ''
    return result
                

def decode_decimal_list(decimals):
    result = ""
    for number in decimals:
        result += chr(number)
    return result

def decode_base64(string):
    string += "="
    message = base64.b64decode(string)
    return message.decode().split()


# ROT13 Function Source: https://www.dotnetperls.com/rot13-python
def rot13(s):
    result = ""

    # Loop over characters.
    for v in s:
        # Convert to number with ord.
        c = ord(v)

        # Shift number back or forward.
        if c >= ord('a') and c <= ord('z'):
            if c > ord('m'):
                c -= 13
            else:
                c += 13
        elif c >= ord('A') and c <= ord('Z'):
            if c > ord('M'):
                c -= 13
            else:
                c += 13

        # Append to result.
        result += chr(c)

    # Return transformation.
    return result


def _decrypt():

    r.recvuntil(b'What does this mean?')
    r.recvline()
    morse = r.recvline().strip().decode()
    decimals = decrypt_morse(morse)
    b64 = decode_decimal_list(decimals)
    rsa_message = decode_base64(b64)
    rot_message = integer_nthroot(int(rsa_message[8]), 3)[0]
    rot_message = long_to_bytes(rot_message).decode()
    print(rot_message)
    plaintext = rot13(rot_message)
    print(plaintext)
    return plaintext

r = remote('crypto.chal.csaw.io', 5001)
r.recvuntil(b'What does this mean?')
r.recvline()
r.recvline()
r.sendline(b'Pokemon Names')
print(r.recvline())
for i in range(5):
    plain = _decrypt()
    print(plain.encode())
    r.sendline(plain.encode())
    print(r.recvline())

print(r.recvline())
print(r.recvline())
print(r.recvline())
