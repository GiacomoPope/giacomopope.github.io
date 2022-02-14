# Commitment Issues

**Authors:** Jack 

**Tags:** crypto

**Points:** 272 (16 solves) 

**Challenge Author:** gripingberry 

**Description:** 

> I created a new commitment scheme, but commitment is scary so I threw away the key.

## Challenge

```python
from random import randrange
from Crypto.Util.number import getPrime, inverse, bytes_to_long, GCD

flag = b'dice{?????????????????????????}'
n = 5

def get_prime(n, b):
	p = getPrime(b)
	while GCD(p - 1, n) != 1:
		p = getPrime(b)
	return p

p = get_prime(n, 1024)
q = get_prime(n, 1024)
N = p*q
phi = (p - 1)*(q - 1)

e = 0xd4088c345ced64cbbf8444321ef2af8b
d = inverse(e, phi)

def sign(message):
	m = bytes_to_long(message)
	return pow(m, d, N)

def commit(s, key, n):
	return (s + key) % N, pow(key, n, N)

def reveal(c1, c2, key, n):
	assert pow(key, n, N) == c2
	return (c1 - key) % N

r = randrange(1, N)
s = sign(flag)
c1, c2 = commit(s, r, n)

print(f'N = {hex(N)}')
print(f'c1 = {hex(c1)}')
print(f'c2 = {hex(c2)}')
```

## Solution

### Reading the Challenge

This challenge is based on a custom commitment scheme for RSA signatures. Before diving into the solution, let's break down what we're given and try and identify the insecure part of the scheme.

The RSA modulus $N=pq$ has 2048 bits, and is the product of two 1024 bit primes, which are generated such that $n = 5$ is not a factor of $(p-1)$ or $(q-1)$. From this alone, we will not be able to factor $N$. 

The public exponent is unusual: `e = 0xd4088c345ced64cbbf8444321ef2af8b`, but it's prime and not so large as to cause much suspicion. So far, so good (or bad for finding a solution, i suppose...).

We are given the length of the `flag` , which is 31 bytes or 248 bits long. The signature of the flag is $s = m^d \pmod N$, where $m$ is not padded before signing. This means that $m$ is relatively small compared to the modulus (Coppersmith should start being a thought we have now). However, we don't have the value of the signature, only the commitment.

The commitment gives us two values, $c_1$ and $c_2$. Let's look at how the commitment is made. 

```python
def commit(s, key, n):
	return (s + key) % N, pow(key, n, N)

r = randrange(1, N)
s = sign(flag)
c1, c2 = commit(s, r, n)
```

First a random number $r$ is generated from `r = randrange(1, N)` as the `key`. The flag is signed and so we are left with two integers $(r,s)$ both approximately of size $N$. The commitment is made by adding together these integers modulo $N$: 

$$
c_1 = (s + r) \pmod N.
$$

We can understand $r$ here as effectively being a OTP, obscuring the signature $s$. We cannot recover $s$ from $c_1$ without knowing $r$ and we cannot recover $r$ without knowing $s$.

The second part of the commitment depends only on the random number $r$ and is given by

$$
c_2 = r^5 \pmod N.
$$

Obtaining $r$ from $c_2$ is as hard as breaking RSA with the public key $(e=5,N)$. If $r$ was small, we could try taking the fifth root, but as it of the size of $N$, we cannot break $c_2$ to recover $r$.

So... either the challenge is impossible, or there's a way to use our knowledge of $(c_1,c_2)$ together to recover the flag. 

### Combining Commitments

Let's write down what we know algebraically:

$$
\begin{aligned}
s &= m^d  &&\pmod N, \\
c_1 &= s + r &&\pmod N, \\
c_2 &= r^5 &&\pmod N.
\end{aligned}
$$

Additionally, we know that $m$ is small with respect to $N$, so if we could write down a polynomial $g(m) = 0 \pmod N$, we could use Coppersmith's small roots to recover $m$ and hence the flag!

**Note**: The following solution was thought up by my teammate, [Esrever](https://twitter.com/esrever_25519), so all credit to him.

Consider the polynomial in the ring $R = (\mathbb{Z}/N\mathbb{Z})[X]$:

$$
f(X) = (c_1 - X)^e \pmod N,
$$

we have the great property that $f(r) = m$. However, written like this, the polynomial will be enormous, as $e$ is a (moderately) large prime [Maybe this is the reason $e$ was chosen to be in the form we see in the challenge].

Esrever's great idea was to work in the quotient ring $K = R[X] / (X^5 - c_2)$, using the additional information we get from $c_2$. This allows us to take the $e$ degree polynomial $f(X)$ and recover a (at most) degree four polynomial by repeatedly substituting in $X^5 = c_2$.

Taking powers of the polynomial, we have that

$$
m^k = f^k(r) = (c_1 - r)^{e\cdot k} \pmod N
$$

The hope was that by taking a set of these polynomials, we could write down a linear combination of $m^k$ such that all $r$ cancel, leaving a univariate polynomial in $m$. This is exactly what we need to find if we hope to solve using small roots.

We were able to accomplish this with a bit of linear algebra. Let's go through step by step.

### Linear Algebra to the Rescue

First let us write the $k^{\text{th}}$ power of $f(X)$ as $f^k(X)$ with coefficients $b_{ki}$: 

$$
f^k(X) = \sum_{i=0}^{4} b_{ki} \cdot X^i
$$

Taking $k \in \\{1,\ldots 5 \\}$ we can write down five degree four polynomials using a $5\times5$ matrix and column vector:

$$
\mathbf{M} = 
\begin{pmatrix} 
b_{10} & b_{11} & b_{12} & b_{13} &  b_{14} \\ 
b_{20} & b_{21} & b_{22} & b_{32} &  b_{24} \\
b_{30} & b_{31} & b_{32} & b_{33} &  b_{34} \\
b_{40} & b_{41} & b_{42} & b_{43} &  b_{44} \\
b_{50} & b_{51} & b_{52} & b_{53} &  b_{54} \\
\end{pmatrix}
\quad 
\mathbf{x} = 
\begin{pmatrix}
X^0 \\
X^1 \\
X^2 \\
X^3 \\
X^4 \\
\end{pmatrix}.
$$

With these, our polynomials can be recovered from matrix multiplication:

$$
\mathbf{F} = \mathbf{M}(\mathbf{x}) = 
\begin{pmatrix}
f^1(X) \\
f^2(X) \\
f^3(X) \\
f^4(X) \\
f^5(X) \\
\end{pmatrix}
$$

To solve the challenge, our goal is to find a vector $\mathbf{a} = (\alpha_1, \alpha_2, \alpha_3, \alpha_4, \alpha_5)^\top$ such that 

$$
\mathbf{M}^\top(\mathbf{a}) = (1,0,0,0,0)^\top.
$$

This is equivalent to finding simultaneous solutions to

$$
\sum_{k=1}^5 \alpha_k \cdot b_{k0} = 1, \quad \sum_{k=1}^5 \alpha_k \cdot b_{kj} = 0, \quad j \in \{1,\ldots 4\}
$$

Practically, finding this vector $\mathbf{a}$, allows us to derive the linear combination

$$
g(m) = \sum_{i=1}^5 \alpha_i f^i(X) = \sum_{i=1}^5 \alpha_i \cdot m^i.
$$

with no dependency on the variable $X$, allowing us to understand $g(m)$ as a univariate polynomial in $m$, precisely what we need for small roots!!

Recovering $\mathbf{a}$ is possible as long as $\mathbf{M}$ has an inverse, as we can write

$$
\mathbf{a} = (\mathbf{M}^\top)^{-1} (1,0,0,0,0)^\top
$$

Using SageMath, this is as easy as

```python
M = ... # Matrix of coefficients
v = vector(Zmod(N), [1,0,0,0,0])
a = M.transpose().solve_right(v)
```

With the polynomial $g(m)$ recovered, we can apply SageMath's `.small_roots()` method on our univariate polynomial and recover the flag!

## Implementation

```python
##################
# Challenge Data #
##################

N  = 0xba8cb3257c0c83edf4f56f5b7e139d3d6ac8adf71618b5f16a02d61b63426c2c275ce631a0927b2725c6cc7bdbe30cd8a8494bc7c7f6601bcee5d005b86016e79919e22da4c431cec16be1ee72c056723fbbec1543c70bff8042630c5a9c23f390e2221bed075be6a6ac71ad89a3905f6c706b4fb6605c08f154ff8b8e28445a7be24cb184cb0f648db5c70dc3581419b165414395ae4282285c04d6a00a0ce8c06a678181c3a3c37b426824a5a5528ee532bdd90f1f28b7ec65e6658cb463e867eb5280bda80cbdb066cbdb4019a6a2305a03fd29825158ce32487651d9bfa675f2a6b31b7d05e7bd74d0f366cbfb0eb711a57e56e6db6d6f1969d52bf1b27b
e  = 0xd4088c345ced64cbbf8444321ef2af8b
c1 = 0x75240fcc256f1e2fc347f75bba11a271514dd6c4e58814e1cb20913195db3bd0440c2ca47a72efee41b0f9a2674f6f46a335fd7e54ba8cd1625daeaaaa45cc9550c566f6f302b7c4c3a4694c0f5bb05cd461b5ca9017f2eb0e5f60fb0c65e0a67f3a1674d74990fd594de692951d4eed32eac543f193b70777b14e86cf8fa1927fe27535e727613f9e4cd00acb8fab336894caa43ad40a99b222236afc219397620ca766cef2fe47d53b07e302410063eae3d0bf0a9d67793237281e0bfdd48255b58b2c1f8674a21754cf62fab0ba56557fa276241ce99140473483f3e5772fcb75b206b3e7dfb756005cec2c19a3cb7fa17a4d17f5edd10a8673607047a0d1
c2 = 0xdb8f645b98f71b93f248442cfc871f9410be7efee5cff548f2626d12a81ee58c1a65096a042db31a051904d7746a56147cc02958480f3b5d5234b738a1fb01dc8bf1dffad7f045cac803fa44f51cbf8abc74a17ee3d0b9ed59c844a23274345c16ba56d43f17d16d303bb1541ee1c15b9c984708a4a002d10188ccc5829940dd7f76107760550fac5c8ab532ff9f034f4fc6aab5ecc15d5512a84288d6fbe4b2d58ab6e326500c046580420d0a1b474deca052ebd93aaa2ef972aceba7e6fa75b3234463a68db78fff85c3a1673881dcb7452390a538dfa92e7ff61f57edf48662991b8dd251c0474b59c6f73d4a23fe9191ac8e52c8c409cf4902eeaa71714

##################
#    Solution    #
##################

R.<X> = PolynomialRing(Zmod(N))
R.<X> = R.quo(X^5 - c2)

f1 = (c1 - X)^e
f2 = f1^2
f3 = f1^3
f4 = f1^4
f5 = f1^5

M = Matrix(Zmod(N), 
    [f1.lift().coefficients(sparse=False),
    f2.lift().coefficients(sparse=False),
    f3.lift().coefficients(sparse=False),
    f4.lift().coefficients(sparse=False),
    f5.lift().coefficients(sparse=False)]).transpose()

v = vector(Zmod(N), [1,0,0,0,0])

sol = list(M.solve_right(v))

K.<m> = PolynomialRing(Zmod(N), implementation='NTL')
g = -1
for i,v in enumerate(sol):
    g += v*m^(i+1)

flag = g.monic().small_roots(X=2**(31*8), beta=1, epsilon=0.05)[0]
print(int(flag).to_bytes(31, 'big'))
```

## Flag

`dice{wh4t!!-wh0_g4ve_u-thE-k3y}`
