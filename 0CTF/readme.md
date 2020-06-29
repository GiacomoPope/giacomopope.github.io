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

Futhermore signing two different messages on the same connection with the same `m0` returns the same codon string. This is starting to feel like (EC)DSA, where `m0` is some kind of nonce generating an `r` value from the base point. For it to be randomised on connection suggests that the basepoint itself is randomised. 

Even assuming we are working in DSA, we have many unknowns:

- Is this ECDSA or DSA? 
- What are the parameters? 
- How is the base point randomised?
- Why is the `r` value encoded into a codon, and how do we reverse this

Even with these hunches I really couldnt make any progress on the challenge without understanding the binary. Luckily for me my team is much better at rev than I am, and they made big progress in understanding what is happening!

#### Step One: Reversing

Analysing the binary, it is found that there are some globally defined constants:

- 43955934961951833386625799
- 33428203490603515565240058682678165019167410746025906092519187676
- ACAGCTUACTAUCAUTTAUTGGCAATUUAAAGGGGTUAATATTTCACTAGAACAAGTATGUACUGTGTUTUGGUUACACAUAGTGGATCGACTATUUCCCCGTAUCGATCUCGAGGTTGCUGGACUCGTA
- UUCAUGUACGTUTUCCCTAUAACGAUTUUCUUTCCATAGCUCCTUCGUCAGTAGGCUUCACCATUUAAUATAATUTCACAATAUCUCTAUAGCCUUGATUTCUGUGTAATCCUGCUUTAGTACUTTTAC

There also seems to be the implementation of `sha256` and a multiplication table using `UAGCT` that looks like it is used to perform arithmetic over $GF(5^n)$. Note that the first of the two integers is prime. 

With out assumption that this cryptosystem is some variant of DSA, we started to think that $q = 43955934961951833386625799$ would be some large prime factor of the group order. Looking at $GF(5^n)$, which would have order $5^n - 1$, we find that $q | (5^{129} - 1)$, suggesting that the group we are working with is $GF(5^{129})$.

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
