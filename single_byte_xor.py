import cryptanalysis

CRYPT = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

CRYPT_B = CRYPT.decode('hex')

decryptions = {}

best_candidate = ''

decryptions = cryptanalysis.find_byte_encrypted_candidates(CRYPT_B)

keys = sorted(decryptions)

for i in range(0,10):
    print(str(keys[i]) + ": " + decryptions[keys[i]] + '\n')

