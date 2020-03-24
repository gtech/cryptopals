# coding: utf-8

import sys

PLAIN_TEXT_HEX = '1c0111001f010100061a024b53535009181c'
KEY_HEX =        '686974207468652062756c6c277320657965'

PLAIN_TEXT_B = PLAIN_TEXT_HEX.decode('hex')
KEY_B = KEY_HEX.decode('hex')

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def xor_char(xs, char):
    return "".join(chr(ord(x) ^ ord(char)) for x in xs)


CRYPT_B = xor_strings(PLAIN_TEXT_B,KEY_B)


CRYPT_HEX = CRYPT_B.encode('hex')


