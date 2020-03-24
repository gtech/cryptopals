import cryptanalysis
import test_strings

cypher = cryptanalysis.repeating_key_xor('ICE',test_strings.rap)

print(cypher)
