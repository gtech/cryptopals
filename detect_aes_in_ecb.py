import cryptanalysis

cipherfile = open('8.txt')

for line in cipherfile:
    plain_text = line.strip().decode('hex')
    result = cryptanalysis.repeated_blocks(plain_text)
    if result:
        print(result)

