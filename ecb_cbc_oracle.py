import CA

plain = 'aoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeuaoeu'

ciphertext = CA.encryption_oracle(plain)
#print(ciphertext)
result = CA.repeated_blocks(ciphertext)

if result:
    print('ecb')
