import cryptanalysis
from Crypto.Cipher import AES

key = 'YELLOW SUBMARINE'

ciphertext = cryptanalysis.open_strip('7.txt').decode('base64')

decryption_suite = AES.new(key, AES.MODE_ECB)
plain_text = decryption_suite.decrypt(ciphertext)

print(plain_text)
