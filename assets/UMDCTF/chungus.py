result_dict = {"decryptions": ["Chungus is the god of thunder.", "Earl grey tea is good for him.", "March is a cold season for me.", "Go and watch boba fett please.", "I am someone who likes to eat!", "Professor Katz taught me this.", "All I got on the exam was a B.", "Cryptography is a cool course!"], "key": "8a619ee676527b384a9fd54f505bab0bbecc96316d2c4fc49a3dbc5af2d5"}                                                                                                                                                                                                                                             
import hashlib
plaintexts = result_dict['decryptions']

pt_str = ''
for pt in plaintexts:
    pt_str += pt

print('UMDCTF{' + hashlib.md5(pt_str.encode()).hexdigest() + '}')
