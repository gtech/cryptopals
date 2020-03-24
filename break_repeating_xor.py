import CA

cyphertext_file = open('6.txt')

cyphertext64 = ''
for line in cyphertext_file:
    cyphertext64 += line.strip()

cyphertext = cyphertext64.decode('base64')

#------------------------------------------------------------------------------------------

#CA.find_key_size(40,2800,cyphertext)
              
#Looks like our KEYSIZES are:
# 1.63270833333: 2
# 2.15125: 3
# 2.39947916667: 4
# 2.59191666667: 5
# 2.65774425287: 29
# 2.74715277778: 6
# 2.7568452381: 7
# 2.80310185185: 9
# 2.836875: 8
# 2.89966666667: 10
# I bet it's 29

#------------------------------------------------------------------------------------------

#This is our keysize to test
block_size = 29
#Consecutive blocks of the block_size length
raw_block_list = list(CA.split_by_n(cyphertext,block_size))
#Key: Key_Index, Value: Key_Index'th byte of every block concatenated together
block_strings = {k:'' for k in range(0,block_size)}


for key_byte_i in range(0,block_size):
    for block in raw_block_list:
        if len(block) > key_byte_i:
            block_strings[key_byte_i] += block[key_byte_i]

#For testing our keys by eye
#decrypted = CA.find_byte_encrypted_candidates(block_strings[0])
#CA.print_top_candidates(decrypted, 1, False)

key_bytes = list()
for n in range(0,block_size):
    decrypted = CA.find_byte_encrypted_candidates(block_strings[n])
    key_bytes.append(chr(CA.get_top_candidate(decrypted)[2]))

#------------------------------------------------------------------------------------------

print(''.join(key_bytes))
print(CA.repeating_key_xor(key_bytes,cyphertext))
