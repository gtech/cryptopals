import CA
#TODO Comments

#TODO Split this into two steps
block_size = 0
for i in range(2,257):
    plain = 'A' * i
    ciphertext = CA.ecb_oracle(plain)
    if CA.detect_ecb_cbc(ciphertext) == 'ECB':
        block_size = i/2
        break

BLOCK_COUNT = (len(ciphertext) - block_size)/block_size

block_dictionary={}
decrypted = ''
while(len(decrypted) < block_size):
    front_buffer = ('A'*(block_size-1-len(decrypted))+decrypted)
    for query_byte in range(0,256):
        front_buffer+=chr(query_byte)
        guess_block = CA.ecb_oracle(front_buffer)[0:block_size]
        block_dictionary[guess_block] = front_buffer
        front_buffer = front_buffer[0:-1]
    plain = ('A'*(block_size-1-len(decrypted)))
    byte_search_block = CA.ecb_oracle(plain)[0:block_size]
    byte = block_dictionary[byte_search_block][-1:]
    decrypted += byte
    print decrypted

plain_text = decrypted
for block_i in range(1,BLOCK_COUNT-1):
    last_decrypted_block = decrypted
    decrypted = ''
    while(len(decrypted) < block_size):
        front_buffer = 'A'*(block_size-1-len(decrypted))
        goal_block = CA.ecb_oracle(front_buffer)[block_size*block_i:block_size*(block_i+1)]
        plain = (last_decrypted_block[len(decrypted)+1:]+decrypted)
        for query_byte in range(0,256):
            plain+=chr(query_byte)
            guess_block = CA.ecb_oracle(plain)[0:block_size]
            if goal_block == guess_block:
                decrypted += chr(query_byte)
                break
            plain = plain[0:-1]
    plain_text += decrypted

print(plain_text)
