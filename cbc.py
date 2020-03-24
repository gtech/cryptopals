import CA
import test_strings

BLOCK_SIZE = 16
IV = '\x00' * BLOCK_SIZE
key = test_strings.YS
ciphertext = CA.open_strip('10.txt').decode('base64')
print(CA.ecb_decrypt(ciphertext,key,IV))

plain = 'aosentuhasocreuhrsacoheurscahoerucarcouh'
cipher = CA.ecb_encrypt(plain,key,IV)
print(CA.ecb_decrypt(cipher,key,IV))
