import cryptanalysis

cyphertext_file = open('4.txt')

candidates = {}

for line in cyphertext_file:
    cypher = line.strip().decode('hex')
    new_cs = cryptanalysis.find_byte_encrypted_candidates(cypher)
    candidates.update(new_cs)

print(str(len(candidates)) + " Total Candidates.")
keys = sorted(candidates)

for i in range(0,5):
    print(str(keys[i]) + ': ' + candidates[keys[i]] + '\n')

