# coding: utf-8
import binascii
from functools import reduce
import pdb
import test_strings
from Crypto.Cipher import AES

english_freq = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, # A-G
                0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
                0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
                0.00978, 0.02360, 0.00150, 0.01974, 0.00074]         # V-Z

ALPHABET= list(map(lambda x: chr(x), range(ord('A'),ord('Z'))))

#ASCII=    list(map(lambda x: chr(x), range(ord(' '),ord('~'))))
ASCII=    list(map(lambda x: chr(x), range(0,127)))

metric = dict(zip(ALPHABET,english_freq))
metric[' '] = 0.1918182
#Adding space is super important

def getChi2(text):
    TEXT_LEN = len(text)
    chi2 = 0
    char_occurance = {k:0 for k in ASCII}
    expected_occurance = {k:0.1 for k in ASCII}
    for c in text:
        if c.upper() in char_occurance:
            char_occurance[c.upper()] += 1
        elif c in ASCII:
            char_occurance[c.upper()] = 1
        else:
            #Non ascii byte detected, skyrocket chi2
            return float('inf')
    for c in metric:
        expected_occurance[c] = metric[c] * TEXT_LEN
    for c in ASCII:
        chi2 += ((char_occurance[c] - expected_occurance[c])**2) / expected_occurance[c]
    return chi2


def find_byte_encrypted_candidates(cyphertext):
    decryptions = {}
    for b in range(0,255):
        decrypted = xor_byte(cyphertext,b)
        score = getChi2(decrypted)
        decryptions[score] = decrypted,cyphertext,b
    return decryptions

def print_top_candidates(candidates, number, keys_only=True):
    keys = sorted(candidates)
    for i in range(0,number):
        if keys_only:
            print(str(keys[i]))
        else:
            print(str(keys[i]) + ': ' + str(candidates[keys[i]]))

def get_top_candidate(candidates):
    keys = sorted(candidates)
    return candidates[keys[0]]

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def xor2(xs, ys):
    return "".join((x ^ y) for x, y in zip(xs, ys))

def xor_chars(c1, c2):
    return chr(ord(c1) ^ ord(c2))

def xor_byte(xs, b):
    return "".join(chr(ord(x) ^ b) for x in xs)

def repeating_key_xor(key,plain):
    cypher = ''
    k = 0
    KEY_LEN = len(key)
    for c in plain:
        cypher += xor_chars(key[k],c)
        k += 1
        k = k % KEY_LEN
    return cypher


def hamming_distance(s1,s2):
    x = xor_strings(s1,s2)
    b = bin(int(binascii.hexlify(x),16))
    distance = 0
    for i in b[2:]:
        distance += int(i)
    return distance


def split_by_n(seq, n):
    s = []
    while seq:
        s.append(seq[:n])
        seq = seq[n:]
    return s

def find_key_size(keysize_max,offset_max,cyphertext):
    key_size_range = range(2,keysize_max)
    offset_range = range(0,offset_max)
    #Dictionary of the hamming distances of certain keysizes
    h_dists = {k:[] for k in key_size_range}
    #o is offset
    for o in offset_range:
        for i in key_size_range:
            s1 = cyphertext[o+0:i-1+o]
            s2 = cyphertext[o+i:(i*2)-1+o]
            #normalized hamming distance
            nhd = hamming_distance(s1,s2)/float(i)
            h_dists[i].append(nhd)

    #So we can sort and print our results
    h_dists2 = {}    
    for k in h_dists:
        h_dists2[reduce(lambda x, y: x + y, h_dists[k]) / len(h_dists[k])] = k

    print(len(cyphertext))
    print_top_candidates(h_dists2,10,False)

def open_strip(file_name):
    ciphertext_file = open(file_name)
    ciphertext = ''
    for line in ciphertext_file:
        ciphertext += line.strip()
    return ciphertext

def open_nostrip(file_name):
    ciphertext_file = open(file_name)
    ciphertext = ''
    for line in ciphertext_file:
        ciphertext += line
    return ciphertext

def repeated_blocks(ciphertext):
    block_sizes = [8,16]
    relevant_blocks = []
    for block_size in block_sizes:
        blocks = split_by_n(ciphertext,block_size)
        for b in blocks:
            count = blocks.count(b)
            if count > 1:
                if b not in relevant_blocks:
                    relevant_blocks.append(b)
    return relevant_blocks

def padding_PKCS7(message,block_size):
    """PKCS#7 padding, slow code but it works"""
    length = len(message)
    if length % block_size != 0:
        full_blocks = int(length/block_size)
        padding_size = block_size - len(message[full_blocks*block_size:])
    return message + '\x40' * padding_size
        
def aes_ecb_decrypt(ciphertext,key):
    decryption_suite = AES.new(key, AES.MODE_ECB)
    return decryption_suite.decrypt(ciphertext)

def aes_ecb_encrypt(plain_text,key):
        plain_text = padding_PKCS7(plain_text)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(plain_text)



