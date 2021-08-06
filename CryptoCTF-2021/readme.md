# CryptoCTF 2021

This year, I played CryptoCTF with CryptoHackers. Full write ups for all challenges are on the [CryptoHack blog](https://blog.cryptohack.org). Below are the write-ups I authored after the event.


## Challenges

| Challenge Name                   | Category              | Points  |
|----------------------------------|-----------------------|--------:|
| [Titu](#titu)                    | Diophantine equations | 69      |
| [Maid](#maid)                    | Rabin Cryptosystem    | 119     |
| [Ferman](#ferman)                | Diophantine equations | 134     |
| [Tiny ECC](#tiny-ecc)            | Elliptic Curves       | 217     |
| [Elegant Curve](#elegant-curve)  | Elliptic Curves       | 217     |
| [RoHaLd](#rohald)                | Edwards Curves        | 180     |
| [My Sieve](#my-sieve)            | RSA                   | 477     |

## Titu
### Challenge

> [Cryptography](https://cr.yp.toc.tf/tasks/Tuti_f9ebebb92f31b4eaefdb6491bdcd7a9c008ad2ec.txz) is coupled with all kinds of equations very much!

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from flag import flag

l = len(flag)
m_1, m_2 = flag[: l // 2], flag[l // 2:]

x, y = bytes_to_long(m_1), bytes_to_long(m_2)

k = '''
000bfdc32162934ad6a054b4b3db8578674e27a165113f8ed018cbe9112
4fbd63144ab6923d107eee2bc0712fcbdb50d96fdf04dd1ba1b69cb1efe
71af7ca08ddc7cc2d3dfb9080ae56861d952e8d5ec0ba0d3dfdf2d12764
'''.replace('\n', '')

assert((x**2 + 1)*(y**2 + 1) - 2*(x - y)*(x*y - 1) == 4*(int(k, 16) + x*y))
```

Given this source, the goal is to solve the equation to obtain both $x,y$.

### Solution

Factoring $k$ we find that it is a perfect square

```python
sage: factor(k)
2^2 * 3^2 * 11^4 * 19^2 * 47^2 * 71^2 * 3449^2 * 11953^2 * 5485619^2 * 2035395403834744453^2 * 17258104558019725087^2 * 1357459302115148222329561139218955500171643099^2
```

Which tells us that moving some terms around, we can write the left hand side as a perfect square too:

```python
sage: f = (x**2 + 1)*(y**2 + 1) - 2*(x - y)*(x*y - 1) - 4*x*y
sage: f
x^2*y^2 - 2*x^2*y + 2*x*y^2 + x^2 - 4*x*y + y^2 + 2*x - 2*y + 1
sage: factor(f)
(y - 1)^2 * (x + 1)^2
```

So we can solve this challenge by looking at the divisors of $\sqrt{4k}$ as we have

$$
(y - 1)^2  (x + 1)^2 = 4k = m
$$

This is easy using Sage's `divisors(m)` function:

```python
factors = [2, 2, 3, 11, 11, 19, 47, 71, 3449, 11953, 5485619, 2035395403834744453, 17258104558019725087, 1357459302115148222329561139218955500171643099]

m = prod(factors) 
 
for d in divs:   
    x = long_to_bytes(d - 1)   
    if b'CCTF{' in x:  
        print(x)  
        y = (n // d) + 1 
        print(long_to_bytes(y))

b'CCTF{S1mPL3_4Nd_N!cE_D'
b'iophantine_EqUa7I0nS!}'
```

##### Flag

`CCTF{S1mPL3_4Nd_N!cE_Diophantine_EqUa7I0nS!}`

## Maid
### Challenge

```python
#!/usr/bin/python3

from Crypto.Util.number import *
from gmpy2 import *
from secret import *
from flag import flag

global nbit
nbit = 1024

def keygen(nbit):
    while True:
        p, q = [getStrongPrime(nbit) for _ in '01']
        if p % 4 == q % 4 == 3:
            return (p**2)*q, p

def encrypt(m, pubkey):
    if GCD(m, pubkey) != 1 or m >= 2**(2*nbit - 2):
        return None
    return pow(m, 2, pubkey)

def flag_encrypt(flag, p, q):
    m = bytes_to_long(flag)
    assert m < p * q
    return pow(m, 65537, p * q)

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "+"
    pr(border*72)
    pr(border, "  hi all, welcome to Rooney Oracle, you can encrypt and decrypt any ", border)
    pr(border, "  message in this oracle, but the flag is still encrypted, Rooney   ", border)
    pr(border, "  asked me to find the encrypted flag, I'm trying now, please help! ", border)
    pr(border*72)

    pubkey, privkey = keygen(nbit)
    p, q = privkey, pubkey // (privkey ** 2)

    while True:
        pr("| Options: \n|\t[E]ncrypt message \n|\t[D]ecrypt ciphertext \n|\t[S]how encrypted flag \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'e':
            pr("| Send the message to encrypt: ")
            msg = sc()
            try:
                msg = int(msg)
            except:
                die("| your message is not integer!!")
            pr(f"| encrypt(msg, pubkey) = {encrypt(msg, pubkey)} ")
        elif ans == 'd':
            pr("| Send the ciphertext to decrypt: ")
            enc = sc()
            try:
                enc = int(enc)
            except:
                die("| your message is not integer!!")
            pr(f"| decrypt(enc, privkey) = {decrypt(enc, privkey)} ")
        elif ans == 's':
            pr(f'| enc = {flag_encrypt(flag, p, q)}')
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()
```

We are given access to an oracle which allows us to encrypt and decrypt data with

$$
c = m^2 \pmod n, \qquad n = p^2 q
$$

and we can request a flag encrypted as

$$
c = m^{e} \pmod {pq}, \qquad e = 65537
$$

Where $p,q$ are 1024 bit primes. The goal is to use the oracle to factor $n$ and hence obtain the flag.

### Solution

The first step is to obtain $n = p^2 q$, which we can do by computing:

$$
n = \gcd(m_1^2 - c_1, m^2_2 - c_2)
$$

by using the oracle to obtain $c_i$ from integers $m_i$. 

Note: there may by other factors, and we actually compute $kn$ for some $k \in \mathbb{Z}$. We can ensure $k = 1$ by computing many $m_i,c_i$ and taking the gcd many times.

The second step is to obtain one of the prime factors.

We cannot send very large numbers to encrypt, but can get around this by sending $E(-X)$ for arbitary sized $X$. As the encryption is simply squaring, this makes no difference. **Defund** noticed that if you decrypt $X = D(2)$ and then compute $E(-X)$, you do not obtain $2$, but rather some very large integer.

I'm not sure how **Defund** solved it, but playing with the numbers while writing it up, I noticed that:

$$
\gcd(n, D(-1) - 1) = p
$$

which allowed me to solve. Looking around online, some other people seem to have solved by doing something like 

$$
\gcd(n, D(m)^2 - m ) = p^2
$$

but seeing as we have no source, a bit of guess work needed to be done one way or another, which seems like a shame.

#### Implementation

```python
from pwn import *
from Crypto.Util.number import *
from math import gcd
import random

r = remote('04.cr.yp.toc.tf', 38010)

def encrypt(msg):
    r.recvuntil(b"[Q]uit")
    r.sendline(b"E")
    r.recvuntil(b"encrypt: ")
    r.sendline(str(msg))
    r.recvuntil(b" = ")
    return int(r.recvline().strip())

def decrypt(msg):
    r.recvuntil(b"[Q]uit")
    r.sendline(b"D")
    r.recvuntil(b"decrypt: ")
    r.sendline(str(msg))
    r.recvuntil(b" = ")
    return int(r.recvline().strip())

def get_flag():
    r.recvuntil(b"[Q]uit")
    r.sendline(b"S")
    r.recvuntil(b" = ")
    return int(r.recvline().strip())

def recover_n():
    # Obtain kn
    m = 2**1536 - random.randint(1,2**1000)
    c = encrypt(m)
    n = m**2 - c
    # Remove all factors of two
    while n%2 == 0:
        n = n // 2
    # Compute a few more GCD to remove any other factors.
    for _ in range(10):
        m = 2**1536 - random.randint(1,2**1000)
        c = encrypt(m)
        n = gcd(n, m**2 - c)
    return n

def dec_flag(p,q):
    c = get_flag()
    d = pow(0x10001, -1, (p-1)*(q-1))
    m = pow(c,d,p*q)
    return long_to_bytes(m)

def recover_factors(n):
    X = decrypt(-1)
    p = gcd(X - 1, n)
    assert isPrime(p)
    q = n // (p*p) 
    assert isPrime(q)
    return p, q

n = recover_n()
p, q = recover_factors(n)
flag = dec_flag(p,q)
print(flag)
# CCTF{___Ra8!N_H_Cryp70_5YsT3M___}
```

##### Flag

`CCTF{___Ra8!N_H_Cryp70_5YsT3M___}`

### Decryption

At the end of the CTF, Factoreal shared the decrypt function. Seeing this, the methods of solving make sense, but it seems like a shame that this wasn't included within the challenge

```python
def decrypt(c, privkey):
    m_p = pow(c, (privkey + 1) // 4, privkey)
    i = (c - pow(m_p, 2)) // privkey
    j = i * inverse(2*m_p, privkey) % privkey
    m = m_p + j * privkey
    if 2*m < privkey**2:
        return m
    else:
        return privkey**2 - m
```

## Ferman
### Challenge

> Modern cryptographic algorithms are the theoretical foundations and the core technologies of information security. Should we emphasize more?
>
> `nc 07.cr.yp.toc.tf 22010`

```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+  hi talented participants, welcome to the FERMAN cryptography task!  +
+  Solve the given equations and decrypt the encrypted flag! Enjoy!    +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

| Parameters generation is a bit time consuming, so please be patient :P
| Options: 
|   [P]rint encrypted flag 
|   [R]eveal the parameters 
|   [Q]uit

P
| encrypt(flag) = 6489656589950752810044571176882070993656025408411955877914111875896024399252967804237101085443293019406006339555779534657926807551928549712558667515175079267695028070934727514846970003337126120540450206565849474378607706030211234939933160392491902242074123763448231072583065175864490510115483208842110529309232348180718641618424365058379284549574700049803925884878710773408472100779358561980206902500388524570616750475958017638946408491011264747032498524679282489181606124604218147

R
    e = 65537
    isPrime(p) = True
    isPrime(q) = True
    n = p * q
    (p - 127)**2 + (q - 184)**2 = 13809252727788824044233595548226590341967726502046327883413398709726819135921363848617960542444505497356040393690402758557636039683075007984614264314802550433942617885990971202110511768121760826488944622697964930982921462840320850014092598270493079542993367042001339267321218767132063176291998391714014192946596879176425904447127657664796094937171819714510504836456988487840790317576922986001688147359646287894578550322731904860694734616037751755921771706899493873123836562784063321
    m = bytes_to_long(flag)
    c = pow(m, e, n) 
    
```

### Solution

On each connection, we are given a flag encrypted using RSA, with additional information in the form

$$
(p - a)^2 + (q - b)^2 = w
$$

On every connection, the integers $a,b,w$ are different, although $a,b$ are usually small ($a,b < 2000$ ).

**Lyutoon** and **Ratman** noticed that factoring $z$, it was always a seventh power $w = z^t$, which means we can write the equation as:

$$
x^2 + y^2 = z^7
$$

We can factor the left hand side by writing:

$$
x^2 + y^2 = (x + iy)(x - iy)
$$

and now we realise that by factoring $z^7$ as a Gaussian integer in $\mathbb{Z}[i]$:

$$
z = \prod_i (a_i + i b_i)
$$

we can obtain $x,y$, as $(x + i y)$ will be a divisor of $z \in \mathbb{Z}[i]$, and from this solve for $p,q$ to grab the flag.

Connecting again, we get:

```python
a = 2265 
b = 902 
w = 24007015341450638047707811509679207068051724063799752621201994109462561550079479155110637624506028551099549192036601169213196430196182069103932872524092047760624845002308713558682251660517182097667675473038586407097498167776645896369165963981698265040400341878755056463554861788991872633206414266159558715922583613630387512303492920597052611976890648632123534922756985895479931541478630417251021677032459939450624439421018438357005854556082128718286537575550378203702362524442461229
flag_enc = 10564879569008106132040759805988959471544940722100428235462653367215001622634768902220485764070394703676633460036566842009467954832811287152142597331508344786167188766356935684044757086902094847810694941751879500776345600036096556068243767090470376672110936445246103465175956767665996275085293250901512809704594905257754009538501795362031873203086994610168776981264025121998840163864902563628991590207637487738286741829585819040077197755226202284847
```

Obtaining the factors of $z \in \mathbb{Z}[i]$ we find:

```python
a = 2265 
b = 902 
z = w^(1/7)
K = ZZ[i]
gaussian_factors = factor(K(z))
# gaussian_factors (-I) * (-1236649975237776943493190425869173*I - 3575914522629734831030006136433790) * (-5*I - 4) * (4*I + 5) * (-1236649975237776943493190425869173*I + 3575914522629734831030006136433790)
```

We now know that $(x + iy)$ is some divisor of $z$, and knowing that $p,q$ are prime, we can find these easily

```python
z_test = (-1236649975237776943493190425869173*I - 3575914522629734831030006136433790)*(4*I + 5)
w_test = z_test**7
x_test = abs(w_test.imag())
y_test = abs(w_test.imag())
p = x_test + a
q = y_test + b

assert is_prime(p)
assert is_prime(q)
assert (p - a)**2 + (q - b)**2 == w
```

Finally, with `p,q` we can solve for the flag

```python
from Crypto.Util.number import *

p = 3515251100858858796435724523870761115321577101490666287216209907489403476079222276536571942496157069855565014771125798502774268554017196492328530962886884456876064742139864478104832820555776577341055529681241338289453827370647829795170813667  
q = 3413213301181339793171422358348736699126965473930685311400429872075816456893055375667482794611435574843396575239764759040242158681190020317082329009191911152126267671754529169503180596722173728126136891139303943035843711591741985591269095977
phi = (p-1)*(q-1)
d = pow(0x10001, -1, phi)
print(long_to_bytes(pow(flag_enc,d,p*q)))
b'CCTF{Congrats_Y0u_5OLv3d_x**2+y**2=z**7}'
```

##### Flag

`CCTF{Congrats_Y0u_5OLv3d_x**2+y**2=z**7}`


## Tiny ECC
### Challenge

> Being Smart will mean completely different if you can use [special numbers](https://cr.yp.toc.tf/tasks/tiny_ecc_f6ba20693ddf6ba78f1537889d2c46a17b7a4d8b.txz)!
>
> `nc 01.cr.yp.toc.tf 29010`

```python
#!/usr/bin/env python3

from mini_ecdsa import *
from Crypto.Util.number import *
from flag import flag

def tonelli_shanks(n, p):
    if pow(n, int((p-1)//2), p) == 1:
            s = 1
            q = int((p-1)//2)
            while True:
                if q % 2 == 0:
                    q = q // 2
                    s += 1
                else:
                    break
            if s == 1:
                r1 = pow(n, int((p+1)//4), p)
                r2 = p - r1
                return r1, r2
            else:
                z = 2
                while True:
                    if pow(z, int((p-1)//2), p) == p - 1:
                        c = pow(z, q, p)
                        break
                    else:
                        z += 1
                r = pow(n, int((q+1)//2), p)
                t = pow(n, q, p)
                m = s
                while True:
                    if t == 1:
                        r1 = r
                        r2 = p - r1
                        return r1, r2
                    else:
                        i = 1
                        while True:
                            if pow(t, 2**i, p) == 1:
                                break
                            else:
                                i += 1
                        b = pow(c, 2**(m-i-1), p)
                        r = r * b % p
                        t = t * b ** 2 % p
                        c = b ** 2 % p
                        m = i
    else:
        return False

def random_point(p, a, b):
    while True:
        gx = getRandomRange(1, p-1)
        n = (gx**3 + a*gx + b) % p
        gy = tonelli_shanks(n, p)
        if gy == False:
            continue
        else:
            return (gx, gy[0])

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "+"
    pr(border*72)
    pr(border, "  Dual ECC means two elliptic curve with same coefficients over the ", border)
    pr(border, "  different fields or ring! You should calculate the discrete log   ", border)
    pr(border, "  in dual ECCs. So be smart in choosing the first parameters! Enjoy!", border)
    pr(border*72)

    bool_coef, bool_prime, nbit = False, False, 128
    while True:
        pr(f"| Options: \n|\t[C]hoose the {nbit}-bit prime p \n|\t[A]ssign the coefficients \n|\t[S]olve DLP \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'a':
            pr('| send the coefficients a and b separated by comma: ')
            COEFS = sc()
            try:
                a, b = [int(_) for _ in COEFS.split(',')]
            except:
                die('| your coefficients are not valid, Bye!!')
            if a*b == 0:
                die('| Kidding me?!! a*b should not be zero!!')
            else:
                bool_coef = True
        elif ans == 'c':
            pr('| send your prime: ')
            p = sc()
            try:
                p = int(p)
            except:
                die('| your input is not valid :(')
            if isPrime(p) and p.bit_length() == nbit and isPrime(2*p + 1):
                q = 2*p + 1
                bool_prime = True
            else:
                die(f'| your integer p is not {nbit}-bit prime or 2p + 1 is not prime, bye!!')
        elif ans == 's':
            if bool_coef == False:
                pr('| please assign the coefficients.')
            if bool_prime == False:
                pr('| please choose your prime first.')
            if bool_prime and bool_coef:
                Ep = CurveOverFp(0, a, b, p)
                Eq = CurveOverFp(0, a, b, q)

                xp, yp = random_point(p, a, b)
                P = Point(xp, yp)

                xq, yq = random_point(q, a, b)
                Q = Point(xq, yq)

                k = getRandomRange(1, p >> 1)
                kP = Ep.mult(P, k)

                l = getRandomRange(1, q >> 1)
                lQ = Eq.mult(Q, l)
                pr('| We know that: ')
                pr(f'| P = {P}')
                pr(f'| k*P = {kP}')
                pr(f'| Q = {Q}')
                pr(f'| l*Q = {lQ}')
                pr('| send the k and l separated by comma: ')
                PRIVS = sc()
                try:
                    priv, qriv = [int(s) for s in PRIVS.split(',')]
                except:
                    die('| your input is not valid, Bye!!')
                if priv == k and qriv == l:
                    die(f'| Congrats, you got the flag: {flag}')
                else:
                    die('| sorry, your keys are not correct! Bye!!!')
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()
```

The challenge is to supply $a,b,p,q=2p+1$ to generate two curves

$$
E_p: y^2 = x^3 + ax + b \pmod p \\ 
E_q: y^2 = x^3 + ax + b \pmod q
$$

The goal of the challenge is to solve the discrete log for a pair of points on each of these curves. Submitting the correct private keys gives you the flag.

### Solution

I solved this challenge in a fairly ugly and inelegant way. So I'll go through it quickly, then discuss what seems to be the intended solution after.

My idea was to generate a curve $E_p$  with $\\#E_p = p$. This is an anomalous curve, and using Smart's attack, the discrete log problem can be moved to solving a simple division by lifting the curve of the p-adics. Then after making one curve easy, I would keep generating primes $p$ until I found a $(q,a,b)$ where $E_q$ had a smooth order, allowing us to solve the discrete log easily.

#### Generating anomalous curves

I refered to [Generating Anomalous Elliptic Curves](http://www.monnerat.info/publications/anomalous.pdf) to generate anomalous curves, and iterated through all primes $p$ where $E_p$   was anomalous. If $q = 2p + 1$ was prime, then I stored the tuple $(p,a,b)$ in a list. I did this until I had plenty of curves to look through.

```python
# http://www.monnerat.info/publications/anomalous.pdf
D = 19
j = -2^15*3^3

def anon_prime(m):
    while True:
        p = (19*m*(m + 1)) + 5
        if is_prime(p):
            return m, p
        m += 1

curves = []
def anom_curve():
    m = 2**61 + 2**60 # chosen so the curves have bit length 128
    while True:
        m, p = anon_prime(m)
        a = (-3*j * inverse_mod((j - 1728), p)) % p
        b = (2*j * inverse_mod((j - 1728), p)) % p
        E = EllipticCurve(GF(p), [a,b])
        
        if E.order() == p:
            G = E.gens()[0]
            print(f'Found an anomalous prime of bit length: {p.nbits()}')
            if is_prime(2*p + 1):
                print(f'Found an anomalous prime with safe prime q = 2p+1. p={p}')
                if p.nbits() != 128:
                    exit()
                curves.append([p,a,b])
                print(curves)
        m += 1
```

Going through curves, I then looked to find $E_q$ of smooth order:

```python
for param in curves:
    p, a, b = param
    q = 2*p + 1
    E1 = EllipticCurve(GF(p), [a,b])
    E2 = EllipticCurve(GF(q), [a,b])
    assert E1.order() == p
    print(factor(E2.order()))
```

Pretty quickly, I found a curve (I think the 15th one?) with order:

```python
E2.order() = 2 * 11 * 29 * 269 * 809 * 1153 * 5527 * 1739687 * 272437559 * 1084044811
```

This is more than smooth enough to solve the dlog (about 10 seconds). 

Sending the parameters to the server:

```python
p = 227297987279223760839521045903912023553
q = 2*p + 1
a = 120959747616429018926294825597988269841 
b = 146658155534937748221991162171919843659
```

I can solve this discrete log using Smart's attack, and the inbuilt discrete log on $E_q$ as it has smooth order.

```python
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

p = 227297987279223760839521045903912023553
q = 2*p + 1
a = 120959747616429018926294825597988269841 
b = 146658155534937748221991162171919843659

Ep = EllipticCurve(GF(p), [a,b])
G = Ep(97161828186858857945099901434400040095,76112161730436240110429589963792144699)
rG = Ep(194119107523766318610516779439078452539,111570625156450061932127850545534033820)

print(SmartAttack(G,rG,p))

Eq = EllipticCurve(GF(q), [a,b])
H = Eq(229869041108862357437180702478501205702,238550780537940464808919616209960416466)
sH = Eq(18599290990046241788386470878953668775,281648589325596060237553465951876240185)

print(H.discrete_log(sH))
```

##### Flag

`CCTF{ECC_With_Special_Prime5}`

### Intended Solution?

Thanks to Ariana for suggeting this solution to me after the CTF ended. 

The challenge checks for $a * b \neq 0$ , but it does not do this modulo the primes, so if we pick any two primes $p, q = 2p+1$  we can send

```python
p = 227297987279223760839521045903912023553
q = 2*p + 1
a = p*(2*p + 1)
b = p*(2*p + 1)
```

Such that the two curves are given by

$$
E_p: y^2 = x^3 + pq x  + pq \pmod p = x^3 \\
E_q: y^2 = x^3 + pq x  + pq \pmod q = x^3 \\ 
$$

Which are singular curves (in particular, these singular curves have triple zeros, known as cusps). We can translate the discrete log over these curves to solving in the additive group of $F_p$   and so the discrete log is division, and trivial. See this [link](https://crypto.stackexchange.com/questions/61302/how-to-solve-this-ecdlp) for an example.

Basically, we use the homomorphism

$$
\phi(x,y) \to \frac{x}{y}
$$

such that we can solve this discrete log in the following way

$$
H = [k] G, \;\; g = \frac{G_x}{G_y}, \;\; h = \frac{H_x}{H_y}, \;\; k = \frac{h}{g}
$$

```python
p = 227297987279223760839521045903912023553
q = 2*p + 1

Fp = GF(p)
Fq = GF(q)

Px, Py = (171267639996301888897655876215740853691,17515108248008333086755597522577521623)
kPx, kPy = (188895340186764942633236645126076288341,83479740999426843193232746079655679683)
k = Fp(Fp(kPx) / Fp(kPy)) / Fp(Fp(Px) / Fp(Py))

Qx, Qy = (297852081644256946433151544727117912742,290511976119282973548634325709079145116)
lQx, lQy = (83612230453021831094477443040279571268,430089842202788608377537684275601116540)
l = Fq(Fq(lQx) / Fq(lQy)) / Fq(Fq(Qx) / Fq(Qy))

print(f'{k}, {l}')
```

However, these primes aren't special (re: the flag), so maybe this also isn't intended?

## ELEGANT CURVE
### Challenge
> Playing with [Fire](https://cr.yp.toc.tf/tasks/elegant_curve_ae8c3f188723d2852c9f939ba87d930398720a62.txz)!
>
> `nc 07.cr.yp.toc.tf 10010`

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
import sys
from flag import flag

def tonelli_shanks(n, p):
    if pow(n, int((p-1)//2), p) == 1:
            s = 1
            q = int((p-1)//2)
            while True:
                if q % 2 == 0:
                    q = q // 2
                    s += 1
                else:
                    break
            if s == 1:
                r1 = pow(n, int((p+1)//4), p)
                r2 = p - r1
                return r1, r2
            else:
                z = 2
                while True:
                    if pow(z, int((p-1)//2), p) == p - 1:
                        c = pow(z, q, p)
                        break
                    else:
                        z += 1
                r = pow(n, int((q+1)//2), p)
                t = pow(n, q, p)
                m = s
                while True:
                    if t == 1:
                        r1 = r
                        r2 = p - r1
                        return r1, r2
                    else:
                        i = 1
                        while True:
                            if pow(t, 2**i, p) == 1:
                                break
                            else:
                                i += 1
                        b = pow(c, 2**(m-i-1), p)
                        r = r * b % p
                        t = t * b ** 2 % p
                        c = b ** 2 % p
                        m = i
    else:
        return False

def add(A, B, p):
    if A == 0:
        return B
    if B == 0:
        return A
    l = ((B[1] - A[1]) * inverse(B[0] - A[0], p)) % p
    x = (l*l - A[0] - B[0]) % p
    y = (l*(A[0] - x) - A[1]) % p
    return (int(x), int(y))

def double(G, a, p):
    if G == 0:
        return G
    l = ((3*G[0]*G[0] + a) * inverse(2*G[1], p)) % p
    x = (l*l - 2*G[0]) % p
    y = (l*(G[0] - x) - G[1]) % p
    return (int(x), int(y))

def multiply(point, exponent, a, p):
    r0 = 0
    r1 = point
    for i in bin(exponent)[2:]:
        if i == '0':
            r1 = add(r0, r1, p)
            r0 = double(r0, a, p)
        else:
            r0 = add(r0, r1, p)
            r1 = double(r1, a, p)
    return r0

def random_point(a, b, p):
    while True:
        x = getRandomRange(1, p-1)
        try:
            y, _ = tonelli_shanks((x**3 + a*x + b) % p, p)
            return (x, y)
        except:
            continue

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "+"
    pr(border*72)
    pr(border, " hi talented cryptographers, the mission is decrypt a secret message", border)
    pr(border, " with given parameters for two elliptic curve, so be genius and send", border)
    pr(border, " suitable parameters, now try to get the flag!                      ", border)
    pr(border*72)

    nbit = 160

    while True:
        pr("| Options: \n|\t[S]end ECC parameters and solve the task \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 's':
            pr("| Send the parameters of first ECC y^2 = x^3 + ax + b like: a, b, p ")
            params = sc()
            try:
                a, b, p = params.split(',')
                a, b, p = int(a), int(b), int(p)
            except:
                die("| your parameters are not valid!!")
            if isPrime(p) and 0 < a < p and 0 < b < p and p.bit_length() == nbit:
                pr("| Send the parameters of second ECC y^2 = x^3 + cx + d like: c, d, q ")
                pr("| such that 0 < q - p <= 2022")
                params = sc()
                try:
                    c, d, q = params.split(',')
                    c, d, q = int(c), int(d), int(q)
                except:
                    die("| your parameters are not valid!!")
                if isPrime(q) and 0 < c < q and 0 < d < q and 0 < q - p <= 2022 and q.bit_length() == nbit:
                    G, H = random_point(a, b, p), random_point(c, d, q)
                    r, s = [getRandomRange(1, p-1) for _ in range(2)]
                    pr(f"| G is on first  ECC and G =", {G})
                    pr(f"| H is on second ECC and H =", {H})
                    U = multiply(G, r, a, p)
                    V = multiply(H, s, c, q)
                    pr(f"| r * G =", {U})
                    pr(f"| s * H =", {V})
                    pr("| Send r, s to get the flag: ")
                    rs = sc()
                    try:
                        u, v = rs.split(',')
                        u, v = int(u), int(v)
                    except:
                        die("| invalid input, bye!")
                    if u == r and v == s:
                        die("| You got the flag:", flag)
                    else:
                        die("| the answer is not correct, bye!")
                else:
                    die("| invalid parameters, bye!")
            else:
                die("| invalid parameters, bye!")
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()
```

The challenge is to supply two elliptic curves

$$
E_p: y^2 = x^3 + ax + b \pmod p \\
E_p: y^2 = x^3 + cx + d \pmod q
$$

Where $0 < q - p < 2023$ and $0 < a,b < p$, $0 < c,d < q$. 

Supplying these curves, you are given two pairs of points and the challenge is to solve this discrete log for both pairs. Supplying the two private keys to the server gives the flag.

### Solution

This challenge I solved in an identical way to [Tiny ECC](#tiny-ecc). I generated an anomalpus curve $E_p$  and then used `q = next_prime(p)`. I then searched for a pair $(c,d)$  where $\\#E_q$  was smooth. I think the intended solution was to generate two singular elliptic curves with smooth primes $p,q$  so you could solve the discrete log in $F_p^{\star}$ , but seeing as the last solution worked, this was already in my mind.

First I needed an anomalous curve with 160 bit prime. Luckily, this is in the paper [Generating Anomalous Elliptic Curves](http://www.monnerat.info/publications/anomalous.pdf) as an example, so I can use their $m$  value. 

Iterating over $c,d$ I found a curve

```python
q = 730750818665451459112596905638433048232067472077
aq = 3
bq = 481
Eq = EllipticCurve(GF(q), [aq,bq])

factor(Eq.order())                                                                                                
2^2 * 3 * 167 * 193 * 4129 * 882433 * 2826107 * 51725111 * 332577589 * 10666075363
```

Which is smooth, with a 34 bit integer as the largest factor.

Sending to the server:

```python
p = 730750818665451459112596905638433048232067471723 
ap = 425706413842211054102700238164133538302169176474 
bp = 203362936548826936673264444982866339953265530166
q = 730750818665451459112596905638433048232067472077
aq = 3
bq = 481
```

I get my two pairs of points I can easily solve the dlog for

```python
from random import getrandbits

# params from http://www.monnerat.info/publications/anomalous.pdf
D = 11
j = -2**15

def anom_curve():
    m = 257743850762632419871495
    p = (11*m*(m + 1)) + 3
    a = (-3*j * inverse_mod((j - 1728), p)) % p
    b = (2*j * inverse_mod((j - 1728), p)) % p
    E = EllipticCurve(GF(p), [a,b])
    G = E.gens()[0]
    return p, a, b, E, G

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)


p = 730750818665451459112596905638433048232067471723 
ap = 425706413842211054102700238164133538302169176474 
bp = 203362936548826936673264444982866339953265530166

Ep = EllipticCurve(GF(p), [ap,bp])
G = Ep(126552689249226752349356206494226396414163660811, 559777835342379827315577715664975494598512818777)
rG = Ep(190128385937465835164338802317889165657442536853, 604514027124204305317929024826237325074492980218)

print(SmartAttack(G,rG,p))

q = 730750818665451459112596905638433048232067472077
aq = 3
bq = 481
Eq = EllipticCurve(GF(q), [aq,bq])

H = Eq(284866865619833057500909264169831974815120720320, 612322665682105897045018564282609259776516527853)
sH = Eq(673590124165798818844330235458561515292416807353, 258709088293250578320930080839442511989120686226)

print(H.discrete_log(sH))
```

Sending the two keys, I get the flag

##### Flag

`CCTF{Pl4yIn9_Wi7H_ECC_1Z_liK3_pLAiNg_wiTh_Fir3!!}`


## RoHaLd
### Challenge

> There is always a [starting point](https://cr.yp.toc.tf/tasks/Rohald_86da9506b23e29e88d8c8f44965e9c2949a3dc41.txz), isn't it?

`RoHaLd_ECC.py`

```python
#!/usr/bin/env sage

from Crypto.Util.number import *
from secret import flag, Curve

def ison(C, P):
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) % p == 0

def teal(C, P, Q):
    c, d, p = C
    u1, v1 = P
    u2, v2 = Q
    assert ison(C, P) and ison(C, Q)
    u3 = (u1 * v2 + v1 * u2) * inverse(c * (1 + d * u1 * u2 * v1 * v2), p) % p
    v3 = (v1 * v2 - u1 * u2) * inverse(c * (1 - d * u1 * u2 * v1 * v2), p) % p
    return (int(u3), int(v3))

def peam(C, P, m):
    assert ison(C, P)
    c, d, p = C
    B = bin(m)[2:]
    l = len(B)
    u, v = P
    PP = (-u, v)
    O = teal(C, P, PP)
    Q = O
    if m == 0:
        return O
    elif m == 1:
        return P
    else:
        for _ in range(l-1):
            P = teal(C, P, P)
        m = m - 2**(l-1)
        Q, P = P, (u, v)
        return teal(C, Q, peam(C, P, m))

c, d, p = Curve

flag = flag.lstrip(b'CCTF{').rstrip(b'}')
l = len(flag)
lflag, rflag = flag[:l // 2], flag[l // 2:]

s, t = bytes_to_long(lflag), bytes_to_long(rflag)
assert s < p and t < p

P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)

print(f'ison(C, P) = {ison(Curve, P)}')
print(f'ison(C, Q) = {ison(Curve, Q)}')

print(f'P = {P}')
print(f'Q = {Q}')

print(f's * P = {peam(Curve, P, s)}')
print(f't * Q = {peam(Curve, Q, t)}')
```

`output.txt`

```python
ison(C, P) = True
ison(C, Q) = True
P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
s * P = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
t * Q = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933)
```

The challenge is to solve the discrete log problem twice, given two pairs of points on the curve. However, before we can do this, we need to recover the curve parameters $(c,d,p)$. The writeup is broken into two pieces: first the recovery of the paramters, then the mapping of the Edwards curve to Weierstrass form to easily solve the dlog using Sage.

### Solution

#### Recovering Curve Parameters

Our goal in this section is to recover $(c,d,p)$ so we can reconstruct the curve and solve the discrete log. We will obtain $p$ first, which will allow us to take inversions mod $p$, needed to recover $c, d$. 

We have the curve equation:

$$
E_{c,d} : x^2 + y^2  = c^2 (1 + d x^2 y^2) \pmod p
$$

and so we know for any point $(x_0,y_0)$  we have

$$
x_0^2 + y_0^2  - c^2 (1 + d x_0^2 y_0^2) = k_0 p \equiv 0\pmod p
$$

for some integer $k_0$. 

Taking two points on the curve, we can isolate $cd^2$  using:

$$
X_1 = x_1^2 + y_1^2  - c^2 (1 + d x_1^2 y_1^2) = k_1 p \\
X_2 = x_2^2 + y_2^2  - c^2 (1 + d x_2^2 y_2^2) = k_2 p
$$

The goal is to use two points to write something which is a multiple of $p$, and to do this twice. We can then recover $p$ from the gcd of the pair of points.

Taking the difference $X_1 - X_2$ elliminates the constant $c^2$ term:

$$
X_1 - X_2 = (x_1^2 - x_2^2 + y_1^2 - y_2^2) - c^2d (x_1^2 y_1^2 - x_2^2 y_2^2) \equiv 0 \pmod p
$$

Collecting the multiples of $p$ we can isolate $c^2 d$ , where we use the notation:

$$
A_{ij} = x_i^2 - x_j^2 + y_i^2 - y_j^2, \qquad B_{ij} = x_i^2 y_i^2 - x_j^2 y_j^2
$$

to write down:

$$
\frac{A_{12}}{B_{12}} \equiv c^2 d \pmod p
$$

Doing this with the other pair of points gives another expression for $c^2 d$ and the difference of these two expressions will be a multiple of $p$

$$
\frac{A_{12}}{B_{12}}  -  \frac{A_{34}}{B_{34}}  = k \cdot p
$$

There's one more problem: we can't divide without knowing $p$, so first let's remove the denominator:

$$
A_{12} B_{34} - A_{34} B_{12} = B_{12}B_{34}kp = \tilde{k} p
$$

Finally, we can obtain $p$ from taking another combination of points and taking the $\gcd$

$$
\begin{aligned}
Y_{1234} &= A_{12} B_{34} - A_{34} B_{12} = B_{12}B_{34} \\
Y_{1324} &= A_{13} B_{24} - A_{24} B_{13} = B_{13}B_{24} \\
p &\simeq \gcd(Y_{1234}, Y_{1324})
\end{aligned}
$$

Note, we may not get exactly $p$ , but some multiple of $p$, however, it's easy to factor this and find $p$  precisely.

Returning to the above expression with the knowledge of $p$, we can compute $c^2d$

$$
c^2 d = \frac{x_1^2 - x_2^2 + y_1^2 - y_2^2 }{x_1^2 y_1^2 - x_2^2 y_2^2} \pmod p
$$

and with this known, we can so back to any point on a curve and write

$$
c^2 = x_0^2 + y_0^2 - c^2 d x_0^2 y_0^2 \pmod p
$$

and $c$ is then found with a square root and $d$ can be found from $c^2 d$. With all curve parameters known, we can continue to solve the discrete log.

```python
from math import gcd

def ison(C, P):
    """
    Verification points are on the curve
    """
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - cc * (1 + d * u**2*v**2)) % p == 0

def a_and_b(u1,u2,v1,v2):
    """
    Helper function used to simplify calculations
    """
    a12 = u1**2 - u2**2 + v1**2 - v2**2
    b12 = u1**2 * v1**2 - u2**2 * v2**2
    return a12, b12

def find_modulus(u1,u2,u3,u4,v1,v2,v3,v4):
    """
    Compute the modulus from four points
    """
    a12, b12 = a_and_b(u1,u2,v1,v2)
    a13, b13 = a_and_b(u1,u3,v1,v3)
    a23, b23 = a_and_b(u2,u3,v2,v3)
    a24, b24 = a_and_b(u2,u4,v2,v4)

    p_almost = gcd(a12*b13 - a13*b12, a23*b24 - a24*b23)

    for i in range(2,1000):
        if p_almost % i == 0:
            p_almost = p_almost // i

    return p_almost

def c_sq_d(u1,u2,v1,v2,p):
    """
    Helper function to computer c^2 d
    """
    a1,b1 = a_and_b(u1,u2,v1,v2)
    return a1 * pow(b1,-1,p) % p

def c(u1,u2,v1,v2,p):
    """
    Compute c^2, d from two points and known modulus
    """
    ccd = c_sq_d(u1,u2,v1,v2,p)
    cc = (u1**2 + v1**2 - ccd*u1**2*v1**2) % p
    d = ccd * pow(cc, -1, p) % p
    return cc, d


P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
sP = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
tQ = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933)

u1, v1 = P
u2, v2 = Q
u3, v3 = sP
u4, v4 = tQ

p = find_modulus(u1,u2,u3,u4,v1,v2,v3,v4)
cc, d = c(u1,u2,v1,v2,p)

C = cc, d, p
assert ison(C, P)
assert ison(C, Q)
assert ison(C, sP)
assert ison(C, tQ)

print(f'Found curve parameters')
print(f'p = {p}')
print(f'c^2 = {cc}')
print(f'd = {d}')

# Found curve
# p = 903968861315877429495243431349919213155709
# cc = 495368774702871559312404847312353912297284
# d = 540431316779988345188678880301417602675534
```

#### Converting to Weierstrass Form

With the curve known, all we have to do is solve the discrete log problem on the Edwards curve. This could be done by using Pohlih-Hellman and BSGS using the functions defined in the file, but instead we map the Edwards curve into Weierstrass form and use sage in built dlog to solve. Potentially there is a smarter way to do this conversion, here I used known mappings to go from Edwards to Montgomery form, then Montgomery form to Weierstrass form. Please let me know if there's a smarter way to do this!

We begin with the Edwards curve:

$$
E_{c,d} : x^2 + y^2  = c^2 (1 + d x^2 y^2) \pmod p
$$

This is in the less usual form, with the factor $c$, so before continuing, we scale $(x,y,d)$ to remove $c$:

$$
x \to \frac{x}{c}, \; \; y \to \frac{y}{c}, \;\; d \to c^4 d
$$

To obtain the more familiar Edwards curve:

$$
E_{c} : x^2 + y^2  = (1 + d x^2 y^2) \pmod p
$$

Note: I am refering to $(x,y,d)$ using the same labels, I hope this doesnt confuse people.

In this more familiar form, I referred to  https://safecurves.cr.yp.to/equation.html to map the curve to the Montgomery curve

$$
E_{A,B}: B v^2 =  u^3 + Au^2 + u \pmod p
$$

With the factor $B$ here, I dont know how to create this curve using Sage, maybe this is possible? This mapping is done by the coordinate transformation

$$
u = \frac{1 + y}{1 - y}, \qquad v = \frac{2(1 + y)}{ x(1 - y)} = \frac{2u}{x}
$$

and the curve parameters are related by

$$
A = \frac{4}{1 - d } - 2 \qquad B = \frac{1}{1 - d }
$$

Finally, we can convert this curve to short Weierstrass form (equations are taken from https://en.wikipedia.org/wiki/Montgomery_curve)

$$
E_{a,b}: Y^2 = X^3 + aX^2 + b \pmod p
$$

My making the coordinate transformations

$$
X = \frac{u}{B} + \frac{A}{3B}, \qquad Y = \frac{v}{B}
$$

and the curve parameters are related by

$$
a = \frac{3 - A^2}{3B^2} \qquad  b = \frac{2A^3 - 9A}{27B^3}
$$

In this form, we can plug the points into the curve using Sage and solve the discrete log. Implementation is given below

#### Grabbing the flag

```python
from Crypto.Util.number import *

# Recovered from previous section
p = 903968861315877429495243431349919213155709
F = GF(p)
cc = 495368774702871559312404847312353912297284
c = F(cc).sqrt()
d = 540431316779988345188678880301417602675534

# Point data from challenge
P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
sP = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
tQ = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933)

x1, y1 = P
x2, y2 = Q
x3, y3 = sP
x4, y4 = tQ

R.<x,y> = PolynomialRing(F)
g = (x^2 + y^2 - cc * (1 + d * x^2*y^2))

# Check the mapping worked!
assert g(x=x1, y=y1) == 0
assert g(x=x2, y=y2) == 0
assert g(x=x3, y=y3) == 0
assert g(x=x4, y=y4) == 0

# Scale: x,y,d to remove c:
# x^2 + y^2 = c^2 * (1 + d * x^2*y^2)
# to:
# x^2 + y^2 = (1 + d * x^2*y^2)

d = F(d) * F(cc)^2
x1, y1 = F(x1) / F(c),  F(y1) / F(c)
x2, y2 = F(x2) / F(c),  F(y2) / F(c)
x3, y3 = F(x3) / F(c),  F(y3) / F(c)
x4, y4 = F(x4) / F(c),  F(y4) / F(c)

h = (x^2 + y^2 - (1 + d * x^2*y^2))

# Check the mapping worked!
assert h(x=x1, y=y1) == 0
assert h(x=x2, y=y2) == 0
assert h(x=x3, y=y3) == 0
assert h(x=x4, y=y4) == 0

# Convert from Edwards to Mont. 
# https://safecurves.cr.yp.to/equation.html
def ed_to_mont(x,y):
    u = F(1 + y) / F(1 - y)
    v = 2*F(1 + y) / F(x*(1 - y))
    return u,v

u1, v1 = ed_to_mont(x1, y1)
u2, v2 = ed_to_mont(x2, y2)
u3, v3 = ed_to_mont(x3, y3)
u4, v4 = ed_to_mont(x4, y4)

e_curve = 1 - F(d)
A = (4/e_curve - 2)
B = (1/e_curve)

# Mont. curve: Bv^2 = u^3 + Au^2 + u
R.<u,v> = PolynomialRing(ZZ)
f = B*v^2 - u^3 - A* u^2 - u

# Check the mapping worked!
assert f(u=u1, v=v1) == 0
assert f(u=u2, v=v2) == 0
assert f(u=u3, v=v3) == 0
assert f(u=u4, v=v4) == 0

# Convert from Mont. to Weierstrass
# https://en.wikipedia.org/wiki/Montgomery_curve
a = F(3 - A^2) / F(3*B^2)
b = (2*A^3 - 9*A) / F(27*B^3)
E = EllipticCurve(F, [a,b])

# https://en.wikipedia.org/wiki/Montgomery_curve
def mont_to_wei(u,v):
    t = (F(u) / F(B)) + (F(A) / F(3*B))
    s = (F(v) / F(B))
    return t,s

X1, Y1 = mont_to_wei(u1, v1)
X2, Y2 = mont_to_wei(u2, v2)
X3, Y3 = mont_to_wei(u3, v3)
X4, Y4 = mont_to_wei(u4, v4)

P = E(X1, Y1)
Q = E(X2, Y2)
sP = E(X3, Y3)
tQ = E(X4, Y4)

# Finally we can solve the dlog
s = P.discrete_log(sP)
t = Q.discrete_log(tQ)

# This should be the flag, but s is broken
print(long_to_bytes(s))
print(long_to_bytes(t))

# b'\x05\x9e\x92\xbfO\xdf1\x16\xb0>s\x93\xc6\xc7\xe7\xa3\x80\xf0'
# b'Ds_3LlipT!c_CURv3'

# We have to do this, as we picked the wrong square-root.
print(long_to_bytes(s % Q.order()))
print(long_to_bytes(t))

# b'nOt_50_3a5Y_Edw4r'
# b'Ds_3LlipT!c_CURv3'
```

##### Flag

`CCTF{nOt_50_3a5Y_Edw4rDs_3LlipT!c_CURv3}`

#### Wrong Root

When recovering the parameters we find:

```py
# Recovered from previous section
p = 903968861315877429495243431349919213155709
F = GF(p)
cc = 495368774702871559312404847312353912297284
c = F(cc).sqrt()
d = 540431316779988345188678880301417602675534
```

however, there are two square roots to consider. By picking the wrong one, we introduce a minus sign in the scaling of the curves from $E_{a,c}$ to $E_{a}$ which creates an issue with the point we consider in $E_{A,B}$. This can be fixed by instead working with

```py
# Recovered from previous section
p = 903968861315877429495243431349919213155709
F = GF(p)
cc = 495368774702871559312404847312353912297284
c = F((-1 * F(cc).sqrt()))
d = 540431316779988345188678880301417602675534
```

which would mean we did not need to take the reduction mod `Q.order()`
