# Coming soon


## Implementation

```py
from Crypto.Util.number import getPrime

def get_pq(SEED):
	p = SEED
	while True:
		p = next_prime(p)
		if p%3 == 2:
			q = p^2 + p + 1
			if is_prime(q):
				return p,q

def get_embedding(prime, order):
	k = 1
	while True:
		if (p^k-1) % order == 0:
			return k
		k += 1
		if k > 10:
			print("Something is broken")
			exit()

# p picked, q = p^1 + p + 1
p,q = get_pq(1<<10)
print(f'p: {p}')
print(f'q: {q}')
print((p^6 - 1).factor())

F = GF(p)
E = EllipticCurve(F,[0,1])
order = E.order()
j_inv = E.j_invariant()
assert j_inv == 0
k = get_embedding(p, order)
assert k == 2

"""
Given p, q = p^1 + p + 1, we now need to do a base change from E/F_p to E' / F_p^2
If we get this right, the order
E'/F_p^2 == q
"""

Fy = GF(p^2)
Ee = E.change_ring(Fy)
prim = Fy.multiplicative_generator()

# for j_inv = 0, use sextic twists
i = 1
if j_inv == 0:
	while i < 6:
		E_twisted = Ee.sextic_twist(Fy(prim^i))
		if E_twisted.order() == q:
			break
		i+=1

print(E_twisted)
print(f"Order of twisted curve: {E_twisted.order()}")

"""
With a supersingular curve of prime order, we can do the MOV attack from E / F_p^2 -> F_p^6
"""

Fy6 = GF(p^6)
E2 = E_twisted
max_val = E2.order()
E6 = E_twisted.change_ring(Fy6)

print(E6)

P = E2.gens()[0]
xP = 123*P
Pe = E6(P)
xPe = E6(xP)

while True:
    R = E6.random_point()
    m = R.order()
    d = gcd(m, P.order())
    Q = (m//d)*R
    if P.order()/Q.order() in ZZ and P.order() == Q.order():
        break

n = P.order()
print('computing pairings')
alpha = Pe.weil_pairing(Q,n)
beta = xPe.weil_pairing(Q,n)

print('computing log')
dd = beta.log(alpha)
assert P*dd == xP
print(dd)
```
