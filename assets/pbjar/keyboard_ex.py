import re


hid_codes = {
        4: 'a',
        5: 'b',
        6: 'c',
        7: 'd',
        8: 'e',
        9: 'f',
        10: 'g',
        11: 'h',
        12: 'i',
        13: 'j',
        14: 'k',
        15: 'l',
        16: 'm',
        17: 'n',
        18: 'o',
        19: 'p',
        20: 'q',
        21: 'r',
        22: 's',
        23: 't',
        24: 'u',
        25: 'v',
        26: 'w',
        27: 'x',
        28: 'y',
        29: 'z',
        30: '1',
        31: '2',
        32: '3',
        33: '4',
        34: '5',
        35: '6',
        36: '7',
        37: '8',
        38: '9',
        39: '0',
        40: '\n',
        42: '\b',
        43: '\t',
        44: ' ',
        45: '-'
}

data = ""
with open('keyboard.pcapng', 'rb') as f:
    data = f.read()

# Regex find all blocks of 72 bytes starting with the header
key_frames = re.findall(b'\xc0\xcc\rf\xc5\x98\xff\xff.{64}', data, re.DOTALL)

# Extract first key code from the frame
key_codes = []
for frame in key_frames:
        # Remove double key stroke for readability
        if frame[-5] == 0:
            key_codes.append(frame[-6])

# Translate key codes to ascii
result = ''
for key in key_codes:
    if key in hid_codes.keys():
        result += hid_codes[key]
print(result)
