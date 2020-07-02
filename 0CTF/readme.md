# 0CTF

I played this CTF as part of the team Organisers. These challenges were solved as a big group effort including British EBFE, Esrever, Robin and V01d. The crypto challenges of this competition were really interesting and challening. I feel lucky to have been able to play with such a talented team, who helped show me how these more advanced challenges can be interpreted and solved. 

## Gene

#### Step Zero: Guessing

Before the crypto side of this challenge can begin the first thing we needed to do was reverse the binary file given with the challenge. While the team worked on the reversing side I played around with the socket and tried to start guessing what might be going on.

Connecting to the server `nc pwnable.org 23334` we are given three options:

```
1. Sign message
2. Verify message
3. Get flag
```

When we want to sign a message, we are asked to supply a length `78` hex string which is refered to as `m0`. Then we are asked for the length of the message we want to sign and finally the message we want to send `m1`. Signing the message we get a tuple back from the server. As an example, signing the message `m1 = "testmessage"` with a value of `m0 = '12'*39`, we obtain the tuple:

```
('UUAGTUCAUTUAGAUACCGAACAUUUTGGAUAGCGCTUGUGUTCCCTCUCACCUTCUGTGUATTCUGCAACUUUUGAGGTTAATTGGUTUACCGAUCCGATUCCGAGUGATCGACAGAATAATGGGUTT', '0761FDDDEDC2C780153E120D0F749F5E3097ADDE8D1531C766B023C525EE37088293581F65B1')
``` 

So now we know where the name `gene` comes from. If we sign the same pair `(m0, m1)` the reply from the server is the same, but if we disconnect we find that both of the values from the signing process change, suggesting a global random number is set on connection. 

Futhermore, signing two different messages on the same connection with the same `m0` returns the same codon string. This is starting to feel like (EC)DSA, where `m0` is some kind of nonce generating an `r` value from the base point. For it to be randomised on connection suggests that the basepoint itself is randomised. 

Even assuming we are working in DSA, we have many unknowns:

- Is this ECDSA or DSA? 
- What are the parameters? 
- How is the base point randomised?
- Why is the `r` value encoded into a codon, and how do we reverse this

Even with these hunches I really couldnt make any progress on the challenge without understanding the binary. Luckily for me my team is much better at rev than I am, and they made big progress in understanding what is happening!

#### Step One: Reversing

Analysing the binary, it is found that there are some globally defined constants:

```
- 43955934961951833386625799
- 33428203490603515565240058682678165019167410746025906092519187676
- ACAGCTUACTAUCAUTTAUTGGCAATUUAAAGGGGTUAATATTTCACTAGAACAAGTATGUACUGTGTUTUGGUUACACAUAGTGGATCGACTATUUCCCCGTAUCGATCUCGAGGTTGCUGGACUCGTA
- UUCAUGUACGTUTUCCCTAUAACGAUTUUCUUTCCATAGCUCCTUCGUCAGTAGGCUUCACCATUUAAUATAATUTCACAATAUCUCTAUAGCCUUGATUTCUGUGTAATCCUGCUUTAGTACUTTTAC
```

There also seems to be the implementation of `sha256` and a multiplication table using `UAGCT` that looks like it is used to perform arithmetic over $GF(5^n)$. Note that the first of the two integers is prime. 

With out assumption that this cryptosystem is some variant of DSA, we started to think that $q = 43955934961951833386625799$ would be some large prime factor of the group order. Looking at $GF(5^n)$, which would have order $5^n - 1$, we find that $(5^{129} - 1) \mod q \equiv 0$, suggesting that the group we are working with is $GF(5^{129})$.

If this is indeed a DSA variant, the hash function would appear to be `sha256`, the group $GF(5^{129})$ and the codon strings would then be an encoding of the elements of $GF(5^{129})$. Futher study of the multiplicaton table allows us to realise the relationship

```python
codon_vals = {'U' : 0, 'A' : 1, 'G' : 2, 'C' : 3, 'T' : 4}
```

and we can imagine the codon string as the concat of the coefficients of a polynomical in $GF(5^{129})$, where the integers `01234` are simply represented by the letters `UAGCT`.

Robin quickly found a way to do this in sage

```python
# Convert from codon string to polynomical coeffs
I = lambda s: list(map(int, s.translate("".maketrans("UAGCT", "01234"))))

# CODON_MOD
m = I("ACAGCTUACTAUCAUTTAUTGGCAATUUAAAGGGGTUAATATTTCACTAGAACAAGTATGUACUGTGTUTUGGUUACACAUAGTGGATCGACTATUUCCCCGTAUCGATCUCGAGGTTGCUGGACUCGTA")

# CODON_BASE
base = J('UUCAUGUACGTUTUCCCTAUAACGAUTUUCUUTCCATAGCUCCTUCGUCAGTAGGCUUCACCATUUAAUATAATUTCACAATAUCUCTAUAGCCUUGATUTCUGUGTAATCCUGCUUTAGTACUTTTAC')

# Define structures
R.<x> = GF(5)['x']
m = R(m)
F = GF(5^129, 'x', modulus=m)
J = lambda s: F(I(s))

# From codon string to element of F
embed = lambda x: int(''.join(map(str, x.polynomial())), 5)

# From element of F to codon string
to_codon = lambda x: ''.join(map(str, x.polynomial())).translate("".maketrans("01234", "UAGCT"))

# Check convertion is working as intended
assert to_codon(base) == 'UUCAUGUACGTUTUCCCTAUAACGAUTUUCUUTCCATAGCUCCTUCGUCAGTAGGCUUCACCATUUAAUATAATUTCACAATAUCUCTAUAGCCUUGATUTCUGUGTAATCCUGCUUTAGTACUTTTAC'
```

We are futher motivated that we are going along the right line by noticing that the product of the two integers is

```python
q = 43955934961951833386625799
n = 33428203490603515565240058682678165019167410746025906092519187676
assert n*q == 5^{129} - 1
```

This suggests that the group order used for the calculations in finding `(r,s)` is stored on the server in two factors. 

All that remains is to identify the two codon strings which are global constants in the binary. If this is going to be DSA-like signing for $GF(5^{192})$ then we are going to need a modulus for the field, and a base point to perform our calculations. We find the constants strings should interpreted as the modulus and base point as

```python
m = "ACAGCTUACTAUCAUTTAUTGGCAATUUAAAGGGGTUAATATTTCACTAGAACAAGTATGUACUGTGTUTUGGUUACACAUAGTGGATCGACTATUUCCCCGTAUCGATCUCGAGGTTGCUGGACUCGTA"
base = "UUCAUGUACGTUTUCCCTAUAACGAUTUUCUUTCCATAGCUCCTUCGUCAGTAGGCUUCACCATUUAAUATAATUTCACAATAUCUCTAUAGCCUUGATUTCUGUGTAATCCUGCUUTAGTACUTTTAC"
```

**Note**: we identify the base point as the lower degree polynomial in the pair of codon strings found in the binary. 

Understanding the core of what we are working with, we now need to reverse the signing function to find out we can exploit it. We did this by opening up openssl 1.1.1 sources in one window and IDA in the other. Then going through functions looking for debug prints (which contain the source filename, line, and function name) we can start to identify each function. For those without prints, we make some guesses comparing decompilation with relevant source modules. The resulting python-interpretation for the signing function was found as

```python
# g_randBn1 < g_bnFieldOrder
# g_randBn2 < g_bnFieldOrder

def sign(m0, m1):
    bn0 = int(m0, 16) + g_randBn2
    r = CODON_BASE ^ bn0 % CODON_MOD
    h = sha256(str(m0) + m1).digest()
    bn2 = bytes_to_long(h) * g_randBn1
    bn2 = (bn2 + bn0) % g_bnFieldOrder
    s = hex(bn2)
    print("The signature is (%s, %s)\n" % (r, s))
```

We see that we control the input, obtain the output and that we have knowledge of `CODON_BASE`,  `CODON_MOD` and `g_bnFieldOrder`. The only unknowns are `g_randBn1` `g_randBn2`. In the following section we will use a pair of messages to recover these values, which we will refer to as $d_0$ and $d_1$ respectively.

#### Step Two: Crypto

From our reversing of the binary, we now understand the signing server as an implementation of some sort of DSA over the finite field $GF(5^{129})$, with a tuple returned by the server: $(r,s)$. 

As an attacker we have the ability to sign arbitary messages supplying a tuple $(m_0, m_1)$, where $m_0$ is a nonce-like value and $m_1$ is the message we wish to sign. The challenge is solved if given a random $m_0$, we are able to successful sign a fixed message $m_1 = \text{show_me_flag}$.

The unknowns preventing us from solving the challenge are two global secret integers $d_0$ and $d_1$, which are set randomly upon connection to the server. From the reversal of the signing, we see that these constants appear in the tuple $(r,s)$ in the form

$$
r = g^{m_0 + d_0} \mod M
$$

$$
s = H(m_0 + m_1)*d_1 + m_0 + d_0 \mod M
$$

As we have access to signing arbitary messages on the server, we can recover the global secrets by signing two messages $m_1$ and $m_1^\prime$, keeping $m_0$ fixed. To keep things short, we will denote the hash of the message as $h_1 = H(m_0 + m_1)$.

Sending the server two sets of data: $(m_0, m_1)$ and $(m_0, m_1^\prime)$ we receive the following data:

$$
s = h_1*d_1 + m_0 + d_0 \mod M \\
s^\prime = h_1^\prime*d_1 + m_0 + d_0 \mod M 
$$

By taking the difference of these two values, we see

$$
s - s^\prime = h_1*d_1 - h_1^\prime*d_1 \mod M \\
$$

allowing us to recover the global secret $d_1$

$$
d_1 = \frac{s - s^\prime}{h_1 - h_1^\prime} \mod M,
$$

getting us half way to the solve. As we have all the following data $(m_0, m_1, h_1, d_1, s)$ we can solve the first signed message to recover $d_0$:

$$
d_0 = s - m_0 - h_1*d_1 \mod M
$$

Equipped with both global secret values is enough to solve the challenge and grab the flag. A full implementation is given below.

#### Implementation

```python
# python script for socket interaction
from gene_interact import sign as rem_sig
from gene_interact import getflag, t as sock

from hashlib import sha256

# Convert from codon string to polynomical coeffs
I = lambda s: list(map(int, s.translate("".maketrans("UAGCT", "01234"))))

# CODON_MOD
m = I("ACAGCTUACTAUCAUTTAUTGGCAATUUAAAGGGGTUAATATTTCACTAGAACAAGTATGUACUGTGTUTUGGUUACACAUAGTGGATCGACTATUUCCCCGTAUCGATCUCGAGGTTGCUGGACUCGTA")

# CODON_BASE
base = J('UUCAUGUACGTUTUCCCTAUAACGAUTUUCUUTCCATAGCUCCTUCGUCAGTAGGCUUCACCATUUAAUATAATUTCACAATAUCUCTAUAGCCUUGATUTCUGUGTAATCCUGCUUTAGTACUTTTAC')

# Define structures
R.<x> = GF(5)['x']
m = R(m)
F = GF(5^129, 'x', modulus=m)
J = lambda s: F(I(s))

# From codon string to element of F
embed = lambda x: int(''.join(map(str, x.polynomial())), 5)

# From element of F to codon string
to_codon = lambda x: ''.join(map(str, x.polynomial())).translate("".maketrans("01234", "UAGCT"))

# Check convertion is working as intended
assert to_codon(base) == 'UUCAUGUACGTUTUCCCTAUAACGAUTUUCUUTCCATAGCUCCTUCGUCAGTAGGCUUCACCATUUAAUATAATUTCACAATAUCUCTAUAGCCUUGATUTCUGUGTAATCCUGCUUTAGTACUTTTAC'

FM = Zmod(5^129 - 1)

def H(a, b):
    x = sha256((a + b).encode()).hexdigest()
    return int(x, 16)

# Dummy variables for testing
global_d0 = 37
global_d1 = next_prime(314) + 37

def sign(m0, m1):
    x = int(m0, 16) + global_d0
    r = to_codon(pow(base, x))
    y = H(m0, m1) * global_d1
    s = hex((x + y) % (5^129 - 1))[2:].zfill(76).upper()
    return (r, s)

def recover_d1(m0, m1, m11, s0, s1):
    h0 = H(m0, m1)
    h1 = H(m0, m11)
    return FM(s1 - s0) / FM(h1 - h0)

def recover_d0(m0, m1, s, d1):
    return FM(s - H(m0, m1) * d1 - int(m0, 16))

if __name__ == "__main__":
    m0 = "d" * 78
    m1 = "blahx"
    m11 = "blahh"
    r0, s0 = rem_sig((m0, m1))
    print("s0", r0, s0)
    r1, s1 = rem_sig((m0, m11))
    print("s1", r1, s1)
    s0, s1 = map(lambda x: int(x, 16), [s0, s1])
    print("d1", d1 := recover_d1(m0, m1, m11, s0, s1))
    print("d0", d0 := recover_d0(m0, m1, s0, d1))
    global_d0 = d0
    global_d1 = d1
    A = sign("12" * 39, "purple")
    B = rem_sig(("12" * 39, "purple"))
    print(A == B)
    print(getflag(sign))
    sock.interact()
```

#### Flag

`flag{TTAUUTCAGUGUGGTTGAAUAUAT}`


## Simple Curves

#### Challenge

```python
#!/usr/bin/env sage

with open('flag', 'rb') as fp:
    flag = fp.read()
assert len(flag) == 37 and flag[:5] == b'flag{' and flag[-1:] == b'}'
flag = int.from_bytes(flag[5:-1], 'big')

F = GF(2**256)
P = PolynomialRing(F, 'u, v')
u, v = P.gens()
PP = PolynomialRing(F, 'w')
w = PP.gens()[0]

h = u^2 + u
f = u^5 + u^3 + 1
c = v^2 + h*v - f
f = f(u=w)
h = h(u=w)

def encode(plain):
    assert plain < 2**256
    x = F.fetch_int(plain)
    y, k = c(u=x, v=w).roots()[0]
    assert k == 1
    return w - x, y

def decode(c):
    x, y = c
    print(list(x))
    print(y)
    x = [i.integer_representation() for i in x]
    y = [i.integer_representation() for i in y]
    return x, y

def add(p1, p2):
    a1, b1 = p1
    a2, b2 = p2
    d1, e1, e2 = xgcd(a1, a2)
    d, c1, c2 = xgcd(d1, b1+b2+h)
    di = PP(1/d)
    a = a1*a2*di*di
    b = (c1*e1*a1*b2+c1*e2*a2*b1+c2*(b1*b2+f))*di
    b %= a

    while a.degree() > 2:
        a = PP((f-b*h-b*b)/a)
        b = (-h-b)%a
    a = a.monic()
    return a, b

def mul(p, k):
    if k == 1:
        return p
    else:
        tmp = mul(p, k//2)
        tmp = add(tmp, tmp)
        if k & 1:
            tmp = add(tmp, p)
        return tmp


e = 65537
c = mul(encode(flag), e)
ctext = decode(c)
print(ctext)
# ([113832590633816699072296178013238414056344242047498922038140127850188287361982, 107565990181246983920093578624450838959059911990845389169965709337104431186583, 1], [60811562094598445636243277376189331059312500825950206260715002194681628361141, 109257511993433204574833526052641479730322989843001720806658798963521316354418])
```

#### Introduction

This challenge is based on hyperelliptic curve cryptography. A hyperelliptic curve $C$, of genus $g$ over a field $K$ is given by the equation

$$
C: y^2 + h(x) y = f(x), \qquad h(x), g(x) \in K[x] 
$$

and the function $h(x)$ is a polynomial of degree not larger than $g$ and $f(x)$ has degree $2g + 1$. A hyperelliptic curve of genus $g = 1$ is an elliptic curve by defintion and we thus understand hyperelliptic curves as a generalisation of elliptic curves.

To apply hyperelliptic curves in a cryptographic setting, we need an additional structure, known as the Jacobian $J$ of the curve (sometimes written as $J(C)$). The Jacobian on a hyperelliptic curve is an Abelian group, and thus has potential for cryptographic implementation through the hardness of the discrete logarithm problem for the group. In elliptic curve cryptography, the Abelian group is the collection of points on the curve (together with the additional point at infinity), and the group structure comes from point addition. For elliptic curves, it can also be shown that the Jacobian of the curve is isomorphic to the group of points on the curve, but this is not true for hyperelliptic curves or arbitary genus. We thus understand the Jacobian as the generalised group we must consider for DLP for (hyper)elliptic curves (we cannot simply work with the collection of points on the hyperelliptic curve for $g \neq 1$).

This challenge is formed around recovering the flag, represented by an integer. The script given above produces a "base point" in the Jacobian of the curve from the flag and then performs scalar multiplication. Symbolically, the flag is lifted into the Jacobian, which we will denote as $G$. The script then performs the operation $Q = dG$ for $d \ in \mathbb{Z}$, $G,Q \in J(C)$ and prints out $Q$ (although not as an element of $J$ anymore, so we will have to lift the data given back into $J$).

The challenge is then defined by the following: given the element of the Jacobian $Q$, and an integer $d$, such that $Q = dG$, find a way to recover $G$. To do this, we must "divide" the given data by `65537` to obtain the flag, *i.e.* we must find the integer $d^{-1}$ such that $d^{-1} dG = G$. We are able to do this by calculating the value of `inverse_mod(65537,jacobian_order)` and so to solve this challenge we must calculate the order of the Jacobian $J(C)$.

In summary, to grab the flag, we need to:

- Lift the data from the challenge into the Jacobian of the hyperelliptic curve
- Calculate the order of the Jacobian 
- Calculate the inverse of `65537` from `inverse_mod(65537,jacobian_order)`
- Perform inverse multiplication on $Q$ to obtain $G = d^{-1} d Q$
- Represent $G$ as an integer to obtain the flag

The difficulty of this challenge was making sage work as I wanted it to, but I suppose the Jacobian order is the core of the intended challenge!

#### Finding the order

To solve this challenge, we need to find the multipicative inverse of `65537` under the action of scalar multiplication in the Jacobian of the Hyperelliptic curve. This requires calculating the order of the Jacobian. To find this, we followed example 56 in [An elementary introduction to hyperelliptic curves](https://www.math.uwaterloo.ca/~ajmeneze/publications/hyperelliptic.pdf).

In our case, we have a curve $C$ of genus $g=2$, defined over $GF(q) = GF(2)$. As a result, our calculation can follow the method outlined on page 30 of the above link.

While solving the challenge, we were first calculaing a value for the order which wasn't an integer. This bug came from incorrectly calculating the values $M_1$, $M_2$ by forgetting to include the point at infinity while counting all points in step 1. We spotted this by running our script against the given example in the lecture notes. Once this was fixed, we found the order for our curve was an integer. An implementation for the calculation of the order is given below

```python
# Paramters and curve
q = 2
n = 256
E_f = lambda x, y: y^2 + (x^2 + x)*y + x^5 + x^3 + 1


# Step 1 
# Note: + 1 in calcs. represents incluing the point at infinity.

def count_points(F):
    return [(x, y) for x in F for y in F if E_f(x, y) == 0]
    
ps1 = count_points(GF(2))
m1 = len(ps1) + 1
print('points in GF(2) =', ps1)
print('M1 =', m1)

ps2 = count_points(GF(4))
m2 = len(ps2) + 1
print('points in GF(4) =', ps2)
print('M2 =', m2)

# Step 2
a1 = m1 - 1 - q
a2 = (m2 - 1 - q^2 + a1^2) / 2
print('a1 =', a1)
print('a2 =', a2)

# Step 3
# X^2 + a1X + (a2 − 2q) = 0 => x^2 - x - 5 = 0 => zeros = (1 +- sqrt(21)) / 2
var('X')
gammas = list(map(lambda x: x.rhs(), solve([X^2 + a1*X + (a2 - 2 * 2) == 0], X)))
print('gammas =', gammas)

# Step 4
# X^2 − gamma1X + q = 0
alpha1 = list(map(lambda x: x.rhs(), solve([X^2 - gammas[0]*X + q == 0], X)))[0]
alpha2 = list(map(lambda x: x.rhs(), solve([X^2 - gammas[1]*X + q == 0], X)))[0]
print('alpha1 =', alpha1)
print('alpha2 =', alpha2)

# Step 5
nj = int(abs(1-alpha1^n)^2 * abs(1-alpha2^n)^2)
print('size of jacobian =', nj)
# 13407807929942597099574024998205846127384782207827457971403006387925941306569427075743805985793764139096494648696821820448189053384542053304334065342873600
```

With the order of the Jacobian, we can find the multiplicative inverse from `inv = inverse_mod(65537, jacobian_order)`. The only remaining step is to take the integers printed as challenge data and lift these back into the Jacobian of the curve. We perform this with the function

```python
F = GF(2**n)
P.<x> = PolynomialRing(F)
f = x^5 + x^3 + 1
h = x^2 + x

C = HyperellipticCurve(f,h,'u,v')
J = C.jacobian()
J = J(J.base_ring())

def data_to_jacobian(data):
      xs, ys = data
      pt_x = P(list(map(F.fetch_int, xs)))
      pt_y = P(list(map(F.fetch_int, ys)))
      pt = (pt_x, pt_y)
      return J(pt)
```

The output of `pt = data_to_jacobian(data)` is an element of `J` and by calculating `inv*pt` we obtain the flag represented as an element of the Jacobian. Representing this as an integer and applying `long_to_bytes` prints the flag.

#### Implementation

```python
from Crypto.Util.number import long_to_bytes

def count_points(F, curve):
    return [(x, y) for x in F for y in F if curve(x, y) == 0]

def jacobian_order(q, n, curve, debug=False):
      # step 1 
      # +1 represents the point at infinity.
      ps1 = count_points(GF(2), curve)
      m1 = len(ps1) + 1
      if debug:
            print('points in GF(2) =', ps1)
            print('M1 =', m1)

      ps2 = count_points(GF(4), curve)
      m2 = len(ps2) + 1
      if debug:
            print('points in GF(4) =', ps2)
            print('M2 =', m2)

      # step 2
      a1 = m1 - 1 - q
      a2 = (m2 - 1 - q^2 + a1^2) / 2
      if debug:
            print('a1 =', a1)
            print('a2 =', a2)

      # step 3
      # X^2 + a1X + (a2 − 2q) = 0 => x^2 - x - 5 = 0 => zeros = (1 +- sqrt(21)) / 2
      var('X')
      gammas = list(map(lambda x: x.rhs(), solve([X^2 + a1*X + (a2 - 2 * 2) == 0], X)))

      # step 4
      # X^2 − gamma1X + q = 0
      alpha1 = list(map(lambda x: x.rhs(), solve([X^2 - gammas[0]*X + q == 0], X)))[0]
      alpha2 = list(map(lambda x: x.rhs(), solve([X^2 - gammas[1]*X + q == 0], X)))[0]
      if debug:
            print('points in GF(2) =', ps1)
            print('M1 =', m1)
            print('points in GF(4) =', ps2)
            print('M2 =', m2)
            print('a1 =', a1)
            print('a2 =', a2)
            print('gammas =', gammas)
            print('alpha1 =', alpha1)
            print('alpha2 =', alpha2)

      # step 5
      nj = int(abs(1-alpha1^n)^2 * abs(1-alpha2^n)^2)
      return nj


def data_to_jacobian(data):
      xs, ys = data
      pt_x = P(list(map(F.fetch_int, xs)))
      pt_y = P(list(map(F.fetch_int, ys)))
      pt = (pt_x, pt_y)
      return J(pt)

q = 2
n = 256
enc_flag = ([113832590633816699072296178013238414056344242047498922038140127850188287361982, 107565990181246983920093578624450838959059911990845389169965709337104431186583, 1], [60811562094598445636243277376189331059312500825950206260715002194681628361141, 109257511993433204574833526052641479730322989843001720806658798963521316354418])

F = GF(2**n)
P.<x> = PolynomialRing(F)
f = x^5 + x^3 + 1
h = x^2 + x

C = HyperellipticCurve(f,h,'u,v')
J = C.jacobian()
J = J(J.base_ring())

E_f = lambda x, y: y^2 + (x^2 + x)*y + x^5 + x^3 + 1
J_order = jacobian_order(q, n, E_f, debug=False)
# J_order = 13407807929942597099574024998205846127384782207827457971403006387925941306569427075743805985793764139096494648696821820448189053384542053304334065342873600

inv = inverse_mod(65537, J_order)
# inv = 744275832722449429303298944771241714015378147795539803469248473980721950551590333728366665796690631826800853440942334601683198440773364510447034953039873

J_point = data_to_jacobian(enc_flag)
flag_point = inv*J_point
flag_int = flag_point[0].coefficients()[0].integer_representation()
# flag_int = 87336973591408809511144500944284390061575902317760214640835643492103517747

flag = long_to_bytes(flag_int).decode()
print('flag{'+flag+'}')
# flag{1nTere5tinG_Hyp3re11iPtic_curv3}
```
