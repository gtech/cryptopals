import sys
#from binascii import unhexlify, b2a_base64
import string

HEX_STR = sys.argv[1].translate(None, string.whitespace)

b64_str = HEX_STR.decode('hex').encode('base64')

#bytes_str = HEX_STR.decode('hex')
#I'm killing your brain like a poisonous mushroom

#print(bytes_str)

#b64_str = codecs.encode(codecs.decode(HEX_STR,'hex'),'base64') # .decode()

print('\n' + b64_str)
