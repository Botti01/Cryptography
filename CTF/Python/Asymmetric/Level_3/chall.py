from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag
import numpy as np

primes = [getPrime(512) for _ in range(10)]
mods = [np.random.choice(primes, 2, replace=False) for _ in range(6)]
mods = [m[0]*m[1] for m in mods]
e = 65537
print(mods)
m = bytes_to_long(flag.encode())
print([pow(m, e, n) for n in mods])
