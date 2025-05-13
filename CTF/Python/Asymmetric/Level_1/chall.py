from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag

p, q = getPrime(64), getPrime(64)
n = p*q
e = 65537
print(n)
m = bytes_to_long(flag)
print(pow(m, e, n))

# 176278749487742942508568320862050211633
# 46228309104141229075992607107041922411
