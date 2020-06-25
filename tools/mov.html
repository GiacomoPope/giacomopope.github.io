# TODO 
- Explaination


## Implementation

```py
from Crypto.Util.number import getPrime

a = 0
b = 1
p = 665179258825259
F = GF(p)
E = EllipticCurve(F,[a,b])
assert E.j_invariant() == 0
order = E.order()
print(is_prime(order))

# Embedding degree is the smallest integer such that
# (p^k - 1) % E.order() == 0
# It is vital to the MOV attack that k is small.
# For supersingular curves, k ≤	6

k = 2 
assert(p^k - 1) % order == 0

# Create something to break by picking a generator, and a private key
# We will use the MOV attack to recover d from (P,Q)
P = E.gens()[0]
Po = P.order()
d = 123456
Q = d*P

# We now take the supersingular curve E and change the finite field such that we consider E' / GF(p^k)
F2.<x> = GF(p^k)
E2 = E.change_ring(F2)
P2 = E2(P)
Q2 = E2(Q)

# Find a random point with the right behaviour
# Not all points work, so we loop until it does
while True:
    R = E2.random_point()
    Ro = R.order()
    g = gcd(Ro, Po)
    S = (Ro//g)*R
    So = S.order()
    if Po/So in ZZ and Po == So:
        break

# Generate pairings
alpha = P2.weil_pairing(S,Po)
beta = Q2.weil_pairing(S,Po)

# Solve dlog in GF(p^k) instead of E / GF(p)
dd = beta.log(alpha)
print(dd)
```
