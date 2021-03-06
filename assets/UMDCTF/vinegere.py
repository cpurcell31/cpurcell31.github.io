from binascii import unhexlify
from Crypto.Util.number import long_to_bytes, bytes_to_long

expected_freq = {'e': 13.0, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3, 'h': 6.1,
                 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.5, 'w': 2.4, 'f': 2.2,
                 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
                 'q': 0.095, 'z': 0.074, ' ': 13.0}


def single_byte_xor_solver(byte_str):
    score_list = list()
    result_list = list()
    for i in range(256):
        result = b''
        for j in range(len(byte_str)):
            result += long_to_bytes(byte_str[j] ^ i)
        result_list.append(result)
        score_list.append(char_frequency_scorer(result.lower()))
    score_index = score_list.index(min(score_list))
    result = result_list[score_index]
    return result, score_index, min(score_list)


def char_frequency_scorer(plain_str):
    # Manipulate bytes to find only possible strings
    char_count = {i: plain_str.count(i) for i in set(plain_str)}

    # Find character frequency of the string if it is a possible solution
    char_freq = char_frequency(char_count, len(plain_str))

    # Score the frequency
    freq_diff = 0
    for key in char_freq.keys():
        if key in expected_freq.keys():
            freq_diff += abs(expected_freq[key]-char_freq[key])/26
        else:
            if char_freq[key] > 0:
                freq_diff += 20
    return freq_diff


def char_frequency(char_dict, length):
    result_dict = {chr(i): 0 for i in range(256)}
    for key in char_dict.keys():
        result_dict[chr(key)] = char_dict[key] / length
    return result_dict


def encrypt_repeating_xor(byte_input, key):
    result = b''
    key_index = 0
    for i in range(len(byte_input)):
        result += long_to_bytes(byte_input[i] ^ key[key_index])
        key_index += 1
        if key_index >= len(key):
            key_index = 0
    return result


def repeating_xor_solver(bytes_str, key_size):
    # Break up ciphertext into key_size blocks
    blocks = [bytes_str[i:i+key_size] for i in range(0, len(bytes_str), key_size)]
    # Transpose key_size blocks into blocks ordered by byte
    ordered_blocks = [b'']*key_size
    for i in range(len(ordered_blocks)):
        for j in range(len(blocks)):
            if i >= len(blocks[j]):
                break
            ordered_blocks[i] += blocks[j][i].to_bytes(1, 'big')

    # Solve each block with single character xor solver
    key = b""
    for i in range(len(ordered_blocks)):
        result, key_part, score = single_byte_xor_solver(ordered_blocks[i])
        key += key_part.to_bytes(1, byteorder='big')
    # Decrypt
    result = encrypt_repeating_xor(bytes_str, key)
    return key, result


def find_xor_key_size(bytes_str):
    distances = list()
    key_sizes = list()
    for i in range(2, 40):
        # why does +1 work better here?????
        b1 = bytes_str[0:i+1]
        b2 = bytes_str[i:i*2+1]
        b3 = bytes_str[i*2:i*3+1]
        b4 = bytes_str[i*3:i*4+1]

        # Average the distances from the 4 blocks of bytes
        distances.append(
            (compute_hamming_distance(b1, b2) / i) +
            (compute_hamming_distance(b1, b3) / i) +
            (compute_hamming_distance(b1, b4) / i) +
            (compute_hamming_distance(b2, b3) / i) +
            (compute_hamming_distance(b2, b4) / i) +
            (compute_hamming_distance(b3, b4) / i) / 6
        )
        key_sizes.append(i)
    return key_sizes[distances.index(min(distances))]


def compute_hamming_distance(b1, b2):
    distance_result_str = bytes_to_long(b1) ^ bytes_to_long(b2)
    binary_rep = bin(distance_result_str)[2:]
    distance = 0
    for char in binary_rep:
        if char == '1':
            distance += 1
    return distance


def detect_single_byte_xor(cipher_strings):
    results_list = list()
    score_list = list()
    for cipher_str in cipher_strings:
        result, key, score = single_byte_xor_solver(cipher_str)
        results_list.append(result)
        score_list.append(score)
    # print(results_list[score_list.index(min(score_list))])
    return results_list[score_list.index(min(score_list))]


with open('ciphertext.txt', 'r') as f:
    line = f.readlines()
    byte_line = unhexlify(line[0][:-1])
    key_size = find_xor_key_size(byte_line)
    key, result = repeating_xor_solver(byte_line, key_size)
    print(key)
    print(result.decode())

