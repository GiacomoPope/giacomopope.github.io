# Cyber Apocalypse CTF 2021

Here are the write-ups to the challenges I helped make for the CTF CryptoHack and Hack the Box collaborated on. As a team, CryptoHack wrote 17 challenges which became the crypto category of the CTF. A full write-up and discussion of the CTF is given on our [blog](https://blog.cryptohack.org/cyber-apocalypse-2021).

## Contents

| Challenge Name                                               | Category                      | Difficulty | Solves |
| ------------------------------------------------------------ | ----------------------------- | ---------- | ------ |
| [Super Metroid](#super-metroid)                              | Elliptic group order          | Medium     | 77     |
| [Forge of Empires](#forge-of-empires)                        | Elgamal message forgery       | Medium     | 95     |
| [Little Nightmares](#little-nightmares)                      | Fermat's little theorem       | Medium     | 86     |
| [Wii Phit](#wii-phit)                                        | Erdős-Straus conjecture       | Hard       | 38     |
| [Hyper Metroid](#hyper-metroid)                              | Hyperelliptic group order     | Insane     | 18     |
| [RuneScape](#runescape)                                      | Imai-Matsumoto implementation | Insane     | 20     |

## Super Metroid
> Samus needs our help! After a day of burning out her Arm Cannon, blasting Metroids and melting the Mother Brain, she's found her ship's maps have all been encrypted. Lucky for her, these aliens still don't know what they're doing and are trying to roll their own crypto. Can you recover the flag from their elliptic protocol?  

### Challenge

```python
from Crypto.Util.number import bytes_to_long, getPrime
from secrets import FLAG

def gen_key():
    from secrets import a,b
    E1 = EllipticCurve(F, [a,b])
    assert E.is_isomorphic(E1)
    key = - F(1728) * F(4*a)^3 / F(E1.discriminant())
    return key

def encrypt(message, key):
    m = bytes_to_long(message)
    e = 0x10001
    G = E.lift_x(Integer(m))
    P = e*G
    return int(P[0])^^int(key)

p = getPrime(256)
F = GF(p)
E = EllipticCurve(F, [1,2])
key = gen_key()

c1 = encrypt(FLAG[:22], 0)
c2 = encrypt(FLAG[22:], key)

print(f'p = {p}')
print(f'c1 = {c1}')
print(f'c2 = {c2}')
```

### Solution

This challenge performs two stages of encryption:

- RSA-like encryption where $P = [e]G$ where $G$ is a point on an elliptic curve where the x-coordinate a flag fragment
- XOR encryption using a key derived from a second elliptic curve where the parameters of the curve are secret

In RSA, decryption is hard without knowing $\phi(N)$, which allows us to compute $d \equiv e^{-1} \mod \phi(N)$. For this challenge, we are looking for:

$$
d = e^{-1} \mod n
$$

where $n$ is the order of the curve. The order of an elliptic curve is efficently calculated using [Schoof's algorithm](https://en.wikipedia.org/wiki/Schoof%27s_algorithm). In SageMath we can use this algorithm to find $n$:

```python
F = GF(p)
E = EllipticCurve(F, [1,2])
n = E.order()
```

Then, just like as in RSA, we can find the inverse of $e$.

**Note for beginners**: when considering RSA what we really want to do is find $m$ from $c = m^e$. We do this by computing $c^d = m^{de} = m$. This wraps around as the order of the element $m$ is at most $\phi(N)$. 

For elliptic curves, our group operation is addition rather than multiplication, and for a point $G$ we know its order is at most $n$. Such that $[n] G = 0$, where $0$ is the identity element of the group operation on the elliptic curve. Think back to RSA again where Euler's theorem gives us $m^{\phi(N)} \equiv 1 \mod N$ and $1$ is the identity element in $F_N^\star$.

For more details on finite fields and the order of group elements see our [blog post](https://blog.cryptohack.org/tetctf-2021).

The second piece of the puzzle is the generation of the key from the function `gen_key()` which using an unknown curve computes

$$
j = 1728 \frac{4a^3}{4a^3 + 27b^2}
$$

where we have used the the discriminant of the ellptic curve is gievn by $\Delta = -16(4a^3 + 27b^2)$.

The value $j$ is a very special invariant of an elliptic curve known as the j-invariant and is the same for all curves which are isomorphic to each other. As we know that the secret curve is isomorphic to the given curve, we can compute $j$ from the curve we are given to derive the key. You can read more about the [j-invariant](https://en.wikipedia.org/wiki/J-invariant) if you're interested.

All that's left is to implement this in sage and grab the flag.

### Implementation

```python
from Crypto.Util.number import long_to_bytes

p = 103286641759600285797850797617629977324547405479993669860676630672349238970323
c1 = 39515350190224022595423324336682561295008443386321945222926612155252852069385
c2 = 102036897442608703406754776248651511553323754723619976410650252804157884591552

F = GF(p)
E = EllipticCurve(F, [1,2])

n = E.order()
d = inverse_mod(0x10001, n)
key = int(E.j_invariant())

P1 = E.lift_x(Integer(c1))
P2 = E.lift_x(Integer(c2^^key))

G1 = d*P1
G2 = d*P2

flag = long_to_bytes(int(G1[0])) + long_to_bytes(int(G2[0]))
print(flag)
# b'CHTB{Counting_points_with_Schoofs_algorithm}'
```

### Flag

`CHTB{Counting_points_with_Schoofs_algorithm}`

## Forge of Empires
> Over thousands of miles, a messenger from the East has arrived with the sacred text. To enable `PHOTON MAN` and crush the aliens with your robot troopers, the messenger needs you to sign your message!  

### Challenge 

```python
from random import randint
from math import gcd
from Crypto.Util.number import long_to_bytes, bytes_to_long

def gen_keys():
    x = randint(1, p-2)
    y = pow(g, x, p)
    return (x, y)

def sign(message: str, x: int):
    while True:
        m = int(message, 16) & MASK
        k = randint(2, p-2)
        if gcd(k, p - 1) != 1:
            continue 
        r = pow(g, k, p)
        s = (m - x*r) * pow(k,-1,p-1) % (p - 1)
        if s == 0:
            continue
        return (r,s)

def verify(message: str, r: int, s: int, y: int):
    m = int(message, 16) & MASK
    if any([x <= 0 or x >= p-1 for x in [m,r,s]]):
        return False
    return pow(g, m, p) == (pow(y, r, p) * pow(r, s, p)) % p

def get_flag(message: str, r: int, s: int, y: int):
    if b'get_flag' not in bytes.fromhex(message):
        return 'Error: message does not request the flag'
    elif verify(message, r, s, y):
        return FLAG
    else:
        return 'Error: message does not match given signature'

if __name__ == "__main__":
    import os
    os.chdir(os.path.abspath(os.path.dirname(__file__)))

    with open("flag.txt", 'rb') as f:
        FLAG = f.read()

    p = 2**1024 + 1657867
    g = 3
    MASK = (2**p.bit_length() - 1)

    x, y = gen_keys()
    print(f"Server's public key: {y}")
    
    print(f'Please send your request message and signature (r,s)')

    message = input('message: ')
    r = int(input('r: '))
    s = int(input('s: '))

    flag = get_flag(message, r, s, y)
    print(flag)
```

### Solution

The intended solution here consists of first generating an existential forgery for the given public key, due to the fact that the message is not being hashed (see e.g. [the section on the Wikipedia page](https://en.wikipedia.org/wiki/ElGamal_signature_scheme#Existential_forgery)), and then hide the flag in there.

The way we can hide the flag in an *existential* forgery, i.e. a forgery where we normally can't control the message, is due to another error in the code: `MASK` is applied when checking the signature, but not when checking the presence of `get_flag`. This allows us to place `get_flag` in bits that get masked out.

Alternatively, there was also an unintended solution, due to `3` not being a generator of the entire group, but only half of it. This allows us to find the order of `g`, `y` and `r`, so that we can make the verification perform the comparison $1 \overset{?}{=} 1 \cdot 1$.

### Implementation 

**Note**: I was lazy and didn't make something which connected to the server, I simply copy pasted the output. 

```python
from random import randint
from math import gcd
from Crypto.Util.number import long_to_bytes, bytes_to_long

p = 2**1024 + 1657867
MASK = (2**p.bit_length() - 1)
g = 3

def forgery(y: int):
    e = randint(1, p-1)
    r = y*pow(g,e,p) % p
    s = -r % (p - 1)
    m = (e*s) % (p-1)
    m += (bytes_to_long(b'get_flag') << 1200)
    M = hex(m)[2:]
    return(M,r,s)

y = int(input('public key: '))
M, r, s = forgery(y)
print(f'M: {M}')
print(f'r: {r}')
print(f's: {s}')
```

### Flag 

`CHTB{Elgamal_remember_to_hash_your_messages!}`


## Little Nightmares

> Never in your darkest moments did your childhood fears prepare you for an alien invasion. To make matters worse, you've just been given a Little homework by the Lady. Defeat this and she will retreat into the night.  

### Challenge

```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint

FLAG = b'CHTB{??????????????????????????????????}'
flag = bytes_to_long(FLAG)

def keygen():
    p, q = getPrime(1024), getPrime(1024)
    N = p*q
    g, r1, r2 = [randint(1,N) for _ in range(3)]
    g1, g2 = pow(g, r1*(p-1), N), pow(g, r2*(q-1), N)
    return [N, g1, g2], [p, q]

def encrypt(m, public):
    N, g1, g2 = public
    assert m < N, "Message is too long"
    s1, s2 = randint(1,N), randint(1,N)
    c1 = m*pow(g1,s1,N) % N
    c2 = m*pow(g2,s2,N) % N
    return [c1, c2]

def decrypt(enc, private):
    c1, c2 = enc
    p, q = private
    m1 = c1 * pow(q, -1, p) * q
    m2 = c2 * pow(p, -1, q) * p
    return (m1 + m2) % (p*q)

public, private = keygen()
enc = encrypt(flag, public)
assert flag == decrypt(enc, private)

print(f'Public key: {public}')
print(f'Encrypted Flag: {enc}')
```

### Solution

This challenge was inspired by a homework question I helped a friend with which was based on the same cryptosystem. The cryptosystem is as follows. 

Two large primes $p$ and $q$ are picked an a public modulus $N = pq$ is formed. Three random integers in $\mathbb{F}_N^\star$: $(g,r_1,r_2)$ are picked and then the public key:

$$
N, \quad g_1 = g^{r_1(p-1)} \pmod N, \quad g_2 = g^{r_2(q-1)} \pmod N
$$

is computed. The private key is $p,q$.

To solve this puzzle, we then need to find the private key given only the public key. As this is possible, we see this cryptosystem is totally broken and not secure at all!

We give you the decrypt function, so all we need to do is factor $N$. 

To do this, we notice that

$$
g_1 \equiv 1 \pmod p, \qquad g_2  \equiv 1 \pmod q
$$

due to Fermat's little theorem that

$$
g^{p-1} \equiv 1 \pmod p \;\; \Rightarrow \;\; g^{r_1(p-1)} \equiv 1^{r_1} \equiv 1 \pmod p
$$

Without taking the modulus, we can write $g_1$ as:

$$
g_1 = g^{r_1(p-1)} = 1 + kp
$$

for some integer $k$ and looking at this modulo the public key we have:

$$
g_1 \mod N = 1 + k p - \ell N 
$$

for some integers $(k, \ell)$. We can do a bit of algebra to show:

$$
g_1 \mod N = 1 + k p - \ell N = 1 + p(k + \ell q)
$$

and from this find $p$ from

$$
\gcd(N, g_1 - 1) = \gcd(pq, p(k + \ell q)) = p
$$

We note you can do exactly the same with $g_2$ and $q$, or simply find $q$ from $q = N / p$.

### Implementation 

```python
from Crypto.Util.number import long_to_bytes
from functools import reduce
import math

public = [15046368688522729878837364795846944447584249939940259042809310309990644722874686184397211078874301515249887625469482926118729767921165680434919436001251916009731653621249173925306213496143518405636216886510423114656445458948673083827223571060637952939874530020017901480576002182201895448100262702822444377134178804257755785230586532510071013644046338971791975792507111644403115625869332161597091770842097004583717690548871004494047953982837491656373096470967389016252220593050830165369469758747361848151735684518721718721910577759955840675047364431973099362772693817698643582567162750607561757926413317531802354973847, 9283319553892803764690461243901070663222428323113425322850741756254277368036028273335428365663191030757323877453365465554132886645468588395631445445583253155195968694862787593653053769030730815589172570039269584478526982112345274390480983685543611640614764128042195018064671336591349166188571572536295612195292864841173479903528383123563226015278849646883506520514470333897880659139687610612049230856991239192330160727258048546502899802982277188877310126410571180236389500463464659397850999622904270520629126455639717497594792781963273264274684421455422023088932590387852813426966580288533263121276557350436900246463, 8170671201621857973407215819397012803619280999847588732628253232283307833188933536560440103969432332185848983745037071025860497584949115721267685519443159539783527315198992420655868110884873218133385835580345201078361745220227561551654718787264374257293351098299807821798471006283753277157555438331734456302990269860368479905882644912688806233577606978042582643369428542665819950283055672363935065844777322370865181261974289403517780920801228770368401030437376412993457855872519154731210534206120823952983817295670102327952847504357905927290367724038039202573992755780477507837498958878434898475866081720566629437645]
enc = [7276931928429452854246342065839521806420418866856294154132077445353136752229297971239711445722522895365037966326373464771601590080627182837712349184127450287007143044916049997542062388957038193775059765336324946772584345217059576295657932746876343366393024413356918508539249571136028895868283293788299191933766033783323506852233709102246103073938749386863417754855718482717665887208176012160888333043927323096890710493237011980243014972091979988123240671317403963855512078171350546136813316974298786004332694857700545913951953794486310691251777765023941312078456072442404873687449493571576308437181236785086220324920, 323136689475858283788435297190415326629231841782013470380328322062914421821417044602586721782266492137206976604934554032410738337998164019339195282867579270570771188637636630571301963569622900241602213161396475522976801562853960864577088622021373828937295792222819561111043573007672396987476784672948287600574705736056566374617963948347878220280909003723932805632146024848076789866573232781595349191010186788284504514925388452232227920241883518851862145988532377145521056940790582807479213216240632647108768886842632170415653038740093542869598364804101879631033516030858720540787637217275393603575250765731822252109]

def decrypt(enc, private):
    sum = 0
    prod = reduce(lambda a, b: a*b, private)
    for a_i, n_i in zip(enc, private):
        p = prod // n_i
        sum += a_i * pow(p, -1, n_i) * p
    return sum % prod

N, g1, g2 = public
p = math.gcd(g1 - 1, N)
q = math.gcd(g2 - 1, N)

f = decrypt(enc, [p,1])
print(long_to_bytes(f))
#b'CHTB{Factoring_With_Fermats_Little_Theorem}''
```

### Flag 

`CHTB{Factoring_With_Fermats_Little_Theorem}`


## Wii Phit 
> The aliens have encrypted our save file from Wii Phit and we're about to lose our 4,869 day streak!! They're even taunting us with a hint. I think the alien's are getting a bit over-confident if you ask me.  

### Challenge 

```python
from Crypto.Util.number import bytes_to_long
from secrets import FLAG,p,q

N = p**3 * q
e = 0x10001
c = pow(bytes_to_long(FLAG),e,N)

print(f'Flag: {hex(c)}')

# Hint

w = 25965460884749769384351428855708318685345170011800821829011862918688758545847199832834284337871947234627057905530743956554688825819477516944610078633662855
x = p + 1328
y = p + 1329
z = q - 1

assert w*(x*z + y*z - x*y) == 4*x*y*z
```

### Intended Solution

This challenge is a straightforward RSA one where the factors of the RSA modulus are found by solving the equation 

$$
w (xz + yz - xy) = 4 xyz
$$

Where the only known value is $w$ and $(x,y,z)$ are related to the prime factors of the modulus: $N = p^3 q$.

Rearrange the above equation, we obtain

$$
\frac{4}{w} = \frac{1}{x} + \frac{1}{y} - \frac{1}{z}
$$

This is a well known Diophantine equation related to the Erdős–Straus conjecture which states that for $n \geq 2$ there is a solution of the equation

$$
\frac{4}{w} = \frac{1}{x} + \frac{1}{y} + \frac{1}{z}
$$

for positive integers $(x,y,z)$.

The equation presented in this challenge is a little easier as the last term is negative. Using that $w$ is odd, we can write 

$$
\frac{4}{w} = \frac{2}{w-1} + \frac{2}{w+1} - \frac{4}{w(w-1)(w+1)}
$$

We can simplify this a little using that $w = 2k + 1$ such that

$$
\frac{4}{w} = \frac{1}{k} + \frac{1}{k+1} - \frac{1}{k (k + 1) (2k + 1)}
$$

From the above relations we have that:

$$
\begin{aligned}
w &= 2k + 1, \\ 
x &= k, \quad y = k + 1, \quad z= k (k + 1) (2k + 1)\\
x &= p + 1328, \quad y = p + 1329, \quad z = q - 1
\end{aligned}
$$

So we can simply solve for our two primes with

$$
k = \frac{w-1}{2}, \quad p = k - 1328, \quad q = k (k + 1) (2k + 1) + 1
$$

Below we implement this in python and solve for the flag.

**Note for beginners** to compute the private exponent $d = e^{-1} \mod \phi(N)$ we need to compute the totient of the public modulus. This is

$$
\phi(N) = p^2 (p-1)(q-1),
$$

where we have used that:

$$
\phi(xy) = \phi(x)\phi(y), \qquad \phi(p^k) = p^{k-1} (p - 1) 
$$

for all co-prime integers $(x,y)$ and all primes $p$. Note that this is different from textbook RSA where:

$$
N = pq, \qquad \phi(N) = (p-1)(q-1).
$$

### Implementation

```python
from Crypto.Util.number import long_to_bytes

# Challenge Data

c = 0x12f47f77c4b5a72a0d14a066fedc80ba6064058c900a798f1658de60f13e1d8f21106654c4aac740fd5e2d7cf62f0d3284c2686d2aac261e35576df989185fee449c20efa171ff3d168a04bce84e51af255383a59ed42583e93481cbfb24fddda16e0a767bff622a4753e1a5df248af14c9ad50f842be47ebb930604becfd4af04d21c0b2248a16cdee16a04b4a12ac7e2161cb63e2d86999a1a8ed2a8faeb4f4986c2a3fbd5916effb1d9f3f04e330fdd8179ea6952b14f758d385c4bc9c5ae30f516c17b23c7c6b9dbe40e16e90d8734baeb69fed12149174b22add6b96750e4416ca7addf70bcec9210b967991e487a4542899dde3abf3a91bbbaeffae67831c46c2238e6e5f4d8004543247fae7ff25bbb01a1ab3196d8a9cfd693096aabec46c2095f2a82a408f688bbedddc407b328d4ea5394348285f48afeaafacc333cff3822e791b9940121b73f4e31c93c6b72ba3ede7bba87419b154dc6099ec95f56ed74fb5c55d9d8b3b8c0fc7de99f344beb118ac3d4333eb692710eaa7fd22
e = 0x10001
w = 25965460884749769384351428855708318685345170011800821829011862918688758545847199832834284337871947234627057905530743956554688825819477516944610078633662855

# Deriving p,q

k = (w - 1) // 2
p = k - 1328
q = k*(k+1)*(2*k+1) + 1

# Solve

N = p**3 * q
phi = p**2*(p-1)*(q-1)
d = pow(e,-1,phi)
m = pow(c,d,N)
print(long_to_bytes(m))
# b'CHTB{Erdos-Straus-Conjecture}'
```
### Flag

`CHTB{Erdos-Straus-Conjecture}`

### Unintended Solution or How `z3` is Magic

During the CTF we heard from a few players who solved this challenge by using the `z3-solver` package. When I made this challenge, I assumed the size of `w` would make this impossible in a reasonable amount of time, but I was wrong!

During playtesting, Robin tried solving this with `z3` and found that the code hung. The crucial piece that we missed during playtesting was to constrain `p,q > 0`. Removing this condition from the below code, `z3` doesnt seem to be able to find the primes. Thanks to `unblvr` and `killerdog` who both messaged us about this solution.

### Unintended Implementation or All hail `z3`

```python
from z3 import *
from Crypto.Util.number import long_to_bytes

c = 0x12f47f77c4b5a72a0d14a066fedc80ba6064058c900a798f1658de60f13e1d8f21106654c4aac740fd5e2d7cf62f0d3284c2686d2aac261e35576df989185fee449c20efa171ff3d168a04bce84e51af255383a59ed42583e93481cbfb24fddda16e0a767bff622a4753e1a5df248af14c9ad50f842be47ebb930604becfd4af04d21c0b2248a16cdee16a04b4a12ac7e2161cb63e2d86999a1a8ed2a8faeb4f4986c2a3fbd5916effb1d9f3f04e330fdd8179ea6952b14f758d385c4bc9c5ae30f516c17b23c7c6b9dbe40e16e90d8734baeb69fed12149174b22add6b96750e4416ca7addf70bcec9210b967991e487a4542899dde3abf3a91bbbaeffae67831c46c2238e6e5f4d8004543247fae7ff25bbb01a1ab3196d8a9cfd693096aabec46c2095f2a82a408f688bbedddc407b328d4ea5394348285f48afeaafacc333cff3822e791b9940121b73f4e31c93c6b72ba3ede7bba87419b154dc6099ec95f56ed74fb5c55d9d8b3b8c0fc7de99f344beb118ac3d4333eb692710eaa7fd22
e = 0x10001
w = 25965460884749769384351428855708318685345170011800821829011862918688758545847199832834284337871947234627057905530743956554688825819477516944610078633662855

p = Int("p")
q = Int("q")
x = p + 1328
y = p + 1329
z = q - 1
s = Solver()
s.add(p>0)
s.add(q>0)
s.add(w*(x*z + y*z - x*y) == 4*x*y*z)
if s.check() == sat:
    m = s.model()
    p = m[p].as_long()
    q = m[q].as_long()

e = 0x10001
N = p**3 * q
phi = p**2*(p-1)*(q-1)
d = pow(e,-1,phi)
m = pow(c,d,N)
print(long_to_bytes(m))
#b'CHTB{Erdos-Straus-Conjecture}'
```

## Hyper Metroid
> Dropping a morph ball bomb, Samus cracked open the floor and dropped down into the guts of Phaaze. At the end of the tunnel is a locked chest containing the hyper beam upgrade. Samus found the encrypted key preserved in a ball of glowing biomass, but can't decode it. Help Samus capture the flag so she can eradicate the alien invasion once and for all.  

### Challenge 

```python
from secrets import flag

def alien_prime(a):
    p = (a^5 - 1) // (a - 1)
    assert is_prime(p)
    return p


def encrypt_flag():
    e = 2873198723981729878912739
    Px = int.from_bytes(flag, 'big')
    P = C.lift_x(Px)
    JP = J(P)
    return e * JP


def transmit_point(P):
    mumford_x = P[0].list()
    mumford_y = P[1].list()
    return (mumford_x, mumford_y)


a = 1152921504606846997
alpha = 1532495540865888942099710761600010701873734514703868973
p = alien_prime(a)

FF = FiniteField(p)
R.<x> = PolynomialRing(FF)

h = 1
f = alpha*x^5

C = HyperellipticCurve(f,h,'u,v')
J = C.jacobian()
J = J(J.base_ring())

enc_flag = encrypt_flag()

print(f'Encrypted flag: {transmit_point(enc_flag)}')
```
### Solution

#### Disclaimer

This discussion is going to be a mix of ways I think about these things, some terrible glossing over of details, and a general drive towards being able to go from maths equations to SageMath. I'm learning this topic as I make challenges like this, so if I'm wrong about anything please pull me up on it and help me be better!

This challenge is essentially the same as [Super Metroid](#super-metroid), where the solution of the puzzle requires computing the order of the group used to hide the flag. The difference here is that rather than an elliptic curve, the flag is encrypted as an element of the Jacobian of a hyperelliptic curve, for which there are no general algorithms which can compute the order of the Jacobian in a reasonable amount of time for the size of the primes we use.

---

**Aside: Jacobian?? I thought we just did points on curves for crypto!**

![](https://blog.cryptohack.org/assets/images/hyper-meme.jpg)

When we do ECC we think about points and we define a group operation on these points which is Abelian which allows us to do things like key-exchanges due to the assumed hardness of the discrete log problem. When we consider hyperelliptic curves, this group law is not defined for the points on the curve but rather specifc sums of points which we call divisors. The Jacobian is the quotient group of these divisors with the so-called principle divisors (I'm being vague on purpose here to keep word count down). For the case for genus-one curves, the Jacobian of the curve is isomorphic to the original curve! It turns out you've been doing working with Jacobians all along without realising. Now we're generalising to hyerelliptic curves from ECC, we need to be more careful and make sure we're working within the Jacobian.

---

The challenge is solved by using that we consider a very special class of hyperelliptic curve whose Jacobian is the quotient of the Jacobian of the famous Fermat curve $X^n + Y^n = 1$. The case for $n = 3$ was considered by Gauss and is one of the canonical examples when discussing point counting on elliptic curves.

In particular, this challenge is solvable because the prime we use in $F_p$ is a generalised Mersenne prime, for which there is a very efficient algorithm to compute the order of the Jacobian of the curve. This is the topic of this write-up.

The discussion we offer here follows Chapter 6 of [Algebraic Aspects of Cryptography](https://www.springer.com/gp/book/9783540634461) by Koblitz, which was the inspiration for this challenge.

In this discussion, we consider $n = 2g + 1$ to be an odd prime, with $g$ the genus of the hyperelliptic curve. The case of $g = 1$ is the special case of elliptic curves, where computing the order can be done with Schoofs algorithm. We will mention the $n = 3$ case again soon, referencing a result via Gauss which will help us double-check how we're using SageMath.

---

**Aside: Genus? I thought that had something to do with topology?** 

Most people come into contact with the notion of genus when they read about topology. A sphere has genus 0, a doughnut and a mug both have genus 1. As a physicist, I think about genus as counting the number of handles the "shape" has.

This intuition comes back when you consider hyperelliptic curves over $\mathbb{C}$. An elliptic curve can be thought of as a torus (🍩) and higher genus hyperelliptic curves as objects with more "holes" or "handles". Anyway... back to the challenge.

---

Let us begin our discussion working with our hyperelliptic curve

$$
C: v^2 + v = u^n
$$

with solutions over $\mathbb{F}\_p$ for some large prime $p$. Cryptographically, we will consider the Jacobian $\mathbb{J}$ of this curve, which is where we will perform our group operations. 

To solve this challenge, we need to know the order of the Jacobian of a particular curve so that we can find the multiplicative inverse of $e$. Before continuing, lets introduce a few more symbols we will need

- $\zeta = e^{2\pi i / n}$ is a nth root of unity and generator of the nth [cyclotomic field](https://en.wikipedia.org/wiki/Cyclotomic_field): $\zeta^n = 1$.
- $\alpha \in \mathbb{F}\_p$ is a non-nth power
- $\chi$ is a *unique* multiplicative map on $\mathbb{F}\_p^{\star}$ such that $\chi(\alpha) = \zeta$
- $\sigma_i$ is an automorpishm (a symmetry) of the field $\mathbb{Q}(\zeta)$ such that $\sigma_i(\zeta) = \zeta^i$

With these pieces, we can write the Jacobi sum of the character $\chi$ with itself as

$$
J(\chi, \chi) = \sum_{y \in \mathbb{F}\_p} \chi(y) \chi(1 - y)
$$

**Woah!! Hang on!! This is a CTF not a maths lecture**

- Don't worry about $\chi$ if you don't want, we wont need it to get the solve
- Read $\sigma_i(\zeta)$ simply as "take $\zeta$ to the ith power"
- We already have $\alpha$, so that's just some number

**Why do I care about Jacobi sums??? Give me the flag!!**

Turns out, the Jacobi sum of this character $\chi$ is exactly what we want to solve this challenge. We will see that the form of the prime $p$ allows us to efficiently compute the value of $J(\chi,\chi)$ and hence solve the challenge via the following identities, quoted from the text without proof. 

The number of points $M$ on the curve $C$ is equal to

$$
M = p + 1 + \sum_{i = 1}^{n-1} \sigma_i(J(\chi,\chi))
$$

Futhermore, the number of points on the Jacobian (*i.e.* the solution to this puzzle) is given by a similar equation

$$
N = \prod_{i = 1}^{n - 1}  \sigma_i(J(\chi,\chi) + 1)
$$

Using the norm map (see our [blog post](https://blog.cryptohack.org/tetctf-2021) from TetCTF2021 if you want to read more about the norm map) we can write this as

$$
N = \mathbb{N} (J(\chi,\chi) + 1)
$$

Now we see if we can efficiently compute $J(\chi,\chi)$ then we can find the order of the curve and hence solve the challenge!

However, before diving into the Jacobi sum, let's cover the final *twist* of the puzzle. We do not consider a curve $C$ as above, but instead a twist of the curve. For integers $i = 0,1$, and $j = 0,\ldots n-1$ valid twists of $C$ are given by:

$$
C: v^2 + v + \frac{1}{4}(1 - \beta^i) = \beta^i \alpha^j u^n
$$

These twists are interesting to us, as we can perform the twists of various curves and compute the order of the Jacobian, looking for curves where this is (divisible by) a large prime, making it suitible for cryptography, in the same way that we look for elliptic curves with small cofactors to protect against an array of attacks.

Looking at our challenge source, we have $i = 0$, $j = 1$ such that the genus-2 curve is given by

$$
C: v^2 + v = \alpha u^5.
$$

The general form for the order of the Jacobian of these twisted curves is given by

$$
N_{i,j} = \mathbb{N} (J(\chi,\chi) + (-1)^i \zeta^j)
$$

and so in our particular example we wish to find

$$
N_{0,1} = \mathbb{N} (J(\chi,\chi) + \zeta).
$$

---

### Aside: Example using Elliptic Curves

Finding $J(\chi,\chi)$ for $n=3$ has a simple solution from a result of Gauss, who found a way to count the number of points on the curve

$$
C: v^2 + v = u^3 
$$

Let us use that:

- We have an integer $a$ such that $a^3 \equiv 1 \mod p$, $a \not\equiv 1 \mod p$.
- $\alpha$ will be a non-cube in $\mathbb{F}\_p$
- $\zeta = \frac{1}{2}(-1 + \sqrt{-3})$

If you want to find $a$, we can simply take $\alpha^{(p-1)/3} \mod p$. 

It turns out, the Jacobi sum in this case can be computed from

$$
J(\chi, \chi) = \pm \zeta^k \gcd(p, a-\zeta) 
$$

Where we consider these all as element in $\mathbb{Z}[\zeta]$. The root of unity $\pm\zeta^k$ is hand-picked such that $J(\chi, \chi) \equiv -1 \mod 3$ in $\mathbb{Z}[\zeta]$.

We mention this because it's an excellent playground to learn how to define these objects in SageMath, where we can compare our solution with `E.order()` to make sure it's all working!

```python
p = 247481649253408897532555115418385747563
F = GF(p)
E = EllipticCurve(F, [0,0,1,0,0])
# Elliptic Curve defined by y^2 + y = x^3 over Finite Field of size 247481649253408897532555115418385747563

# Find an element of order 3
g = F.multiplicative_generator()
a = g^((p-1)/3)
assert a^3 == 1

# Define zeta
k = CyclotomicField(3)
zeta = k.gen()

# Define Euclidean Ring ZZ[zeta]
ER = QuadraticField(-3).ring_of_integers()

# Comute the Jacobi sum
zetak = -1
J = zetak*gcd(ER(p), ER(a) - ER(zeta))

# Note: we picked zetak such that
assert ER(J).mod(3) == ER(-1).mod(3)

# Compute order and check
N = norm(J + 1)
assert E.order() == N
```

This is **very fast** using only $O(\log^3 p)$ operations, compared to Schoof's algorithm which is also fast:  $O(\log^8 p)$ and works in a far more general setting.

---

It turns out, we picked a hyperelliptic curve where this treatment nicely generalises! Lucky you. We have that for $n = 2g + 1 \geq 5$, with our prime $p$ in the special form

$$
p = \frac{a^n - 1}{a-1},
$$

we can apply a similar method to compute the Jacobi sum. A prime of this form is called a [generalised Mersenne prime](https://link.springer.com/referenceworkentry/10.1007%2F978-1-4419-5906-5_32).

Referencing the text, the expression for $J(\chi, \chi)$ we want to compute is given by

$$
J(\chi, \chi) = \pm \zeta^k \prod_{i=1}^g (a - \sigma_i^{-1} (\zeta)),
$$

where now we pick $\pm \zeta^k$ such that

$$
J(\chi, \chi) \equiv -1 \mod (\zeta - 1)^2
$$

in the ring $\mathbb{Z}[\zeta]$.

In the text, it is explained that for $n=5$, we can just tabulate $\zeta^k$ choices by computing $a \mod 5$ using that

$$
\zeta^j = (1 + \zeta - 1)^j \equiv 1 + j(\zeta - 1) \mod (\zeta - 1)^2
$$

| $a \mod 5$ | $\pm \zeta^k$ |
| -------- | -------- 
| 0     | $-\zeta$     |
| 2     | $-\zeta^4$     |
| 3     | $\zeta^2$    |
| 4     | $\zeta^3$     |

However there are so few options, we could simply enumerate them in a loop and stop when we obey our congruence

```python
n = 5
g = 2
k = CyclotomicField(n)
ER = QuadraticField(-n).ring_of_integers()
zeta = k.gen()
for i in range(2):
    for j in range(n):
        zetak = (-1)^i * (zeta)^n
        J = zetak * prod([ (k(a) - zeta^(1/l) ) for l in range(1,g+1)])
        if ER(J).mod((zeta - 1)^2) == ER(-1).mod((zeta - 1)^2):
            print(i,j)
            exit()
```

All that's left is to take the work from the earlier example and the details from our elliptic curve example and put it into SageMath!

### Implementation 

```python
def data_to_jacobian(data):
    xs, ys = data
    pt_x = R(list(map(FF, xs)))
    pt_y = R(list(map(FF, ys)))
    pt = (pt_x, pt_y)
    return J(pt)

def alien_prime(a):
    p = (a^5 - 1) // (a - 1)
    assert is_prime(p)
    return p

def find_order(a,i,j):
    g = 2
    n = 5
    p = (a^n - 1) // (a - 1)

    k = CyclotomicField(n)
    zeta = k.gen()

    r = a % 5
    if r == 0:
        zetak = -zeta
    elif r == 2:
        zetak = -zeta^4
    elif r == 3:
        zetak = zeta^2
    elif r == 4:
        zetak = zeta^3

    J = zetak * prod([ (k(a) - zeta^(1/l) ) for l in range(1,g+1)])
    N = norm(J + (-1)^i * zeta^j)
    return N

a = 1152921504606846997
p = alien_prime(a)
alpha = 1532495540865888942099710761600010701873734514703868973

FF = FiniteField(p)
R.<x> = PolynomialRing(FF)

h = 1
f = alpha*x^5

C = HyperellipticCurve(f,h,'u,v')
J = C.jacobian()
J = J(J.base_ring())

enc_flag = ([1276176453394706789434191960452761709509855370032312388696448886635083641, 989985690717445420998028698274140944147124715646744049560278470410306181, 1], [617662980003970124116899302233508481684830798429115930236899695789143420, 429111447857534151381555500502858912072308212835753316491912322925110307])

JQ = data_to_jacobian(enc_flag)
order = find_order(a, 0, 1)
e = 2873198723981729878912739
d = inverse_mod(e, order)

rec_JP = d*JQ
rec_x = rec_JP[0].roots()[0][0]
print(int(rec_x).to_bytes(28, 'big'))
#b'CHTB{hyp3r_sp33d_c0unting!!}'
```

### Flag 

`CHTB{hyp3r_sp33d_c0unting!!}`

## RuneScape
###### Authors: Robin & Jack
> This is an old game, and seeing how big the output file is, I understand where the M in MMO comes from...  

The main difficulty for this challenge is not actually in breaking the cryptography (which we will cover further on), but rather in reading, understanding and implementing the presented math and cryptoscheme. As such, it was originally intended as a 3⭐ challenge, but considering the target audience on the HackTheBox platform was likely to be very intimidated by the math in the pdf, we decided it would probably fit better as 4⭐.

The presented cryptosystem is a (slightly simplified) version of the scheme by Imai and Matsumoto. The main part of the implementation comes down to converting between different representations of the values we're working with, doing matrix multiplication, and exponentiation over a finite field.

It's tricky to elaborate a lot further on the math side of this without having too much of a repetition of the content of the pdf itself. Rather, we will briefly elaborate on the only part that was required to actually break it/solve the challenge. First, notice that generating the public key is a major pain, and is not actually required to solve the challenge. We can simply use the private key representation and use it "in the other direction" to perform the public key action. The public key that is embedded in the provided file is also entirely superfluous otherwise. The only part of the private key we're missing is $\theta$ or $h = q^\theta + 1$. Since $q^n + 1 \equiv 1 \pmod{q^n}$ (where $q^n$ is used as a modulus because that is the size of the field we work in), this already leaves at most $n$ potential privates keys. When we further restrict this to values of $\theta$ that result in a value of $h$ that is invertible, as per the requirements of the cryptosystem, we are left with a tiny amount. Simply enumerating all of these and performing the required encryption and decryption then gives us the flag.

For a better understanding of the math and the implementation in sage, we recommend going through Jack's commented implementation below.

Originally, our idea for this challenge was to implement the entire cryptosystem, including generating the actual public key, but unfortunately, it became either very hard or very artificial to do this in a nice way. The public key generation is probably the hardest part of implementing this cryptosystem, and often requires a fair bit of fighting with sage and multivariate polynomial rings to get some semblance of "symbolic" computations.

Our experiments and implementaiton of this can be found in the github repository but are probably too big to include in this post.

*Fun fact*: there was an easter egg in the provided PDF file that hints at why the challenge is named the way it is. When you look at the metadata, you'll find the following title:
> MMO might actually just stand for massive multivariate output

### Implementation

Here's Jack's fairly ugly playtest solution which, although not quite as beautiful as Robin's, has some additional comments made throughout. Considering a big chunk of this challenge was learning how to correctly implement certain pieces of the paper, we hope this helps!

Think of this as a writeup of how the SageMath side of things worked, nested within the main write up!

```python
def string_to_sage(maths):
    """
    Reads a string from the output file and returns
    a parsed sage interpretation of the string
    """
    return eval(preparse(maths.strip()))

def file_to_sage(line_number, split_str):
    """
    Reutrns a parsed string which can be manipulated by 
    SageMath given the line number of the file and where
    to split the line.
    """
    maths_string = data[line_number].split(split_str)[-1]
    return string_to_sage(maths_string)

def from_V_to_bytes(V):
    """
    Returns a bytes string from an element of \mathbb{V}
    """
    bs = []
    for x in V:
        bs.append(x.integer_representation())
    return bytes(bs)

def xor_bytes(b1, b2):
    return bytes([a^^b for a,b in zip(b1,b2)])

# Read the file as lines (string)
with open('output.txt') as f:
    data = f.readlines()

# Construct element x of field GF(2)
x = GF(2)['x'].gen()

# Use this to create F_2^8 with a basis element called alpha 
# to match output.txt
modulus = x^8 + x^4 + x^3 + x^2 + 1
F.<alpha> = GF(2^8, name="alpha", modulus=modulus)

# Now lets make a polynomial ring with X as the generator
R.<X> = F['X']

# This polynomial is a mess, so we pull it from the file 
# rather than paste it in
irr_poly = file_to_sage(3, ' 2^8 with modulus ')

# Finally, we get our extension field K by taking the quotient
# with our irreducible polynomial
K.<X> = R.quotient_ring(irr_poly)

n = irr_poly.degree()
assert n == 60 # match with statement in Section 4


"""
To solve this challenge, we need to take elements from output 
and correctly perform encryption AND decryption. Lets start by
definining our functions.

The function phi, phi inverse can be computed from our basis
"""
beta = [X^i for i in range(n)]

"""
We will need this to add zeros as x.list() so it is length n. 
x.list() only gives up to highest order (cuts off trailing 0)
Kinda annoying... If you know a better way, let us know!
"""
def pad_list_x(x):
    return x.list() + [0]*(n - len(x.list()))

"""
Okay, now we can define phi and its inverse
"""
# phi: K -> V
def phi(x):
    return vector(F, pad_list_x(x))

# phi^-1: V -> K
def phi_inv(a_vec):
    return sum(a*b for a, b in zip(a_vec, beta))

"""
The function psi is just exponentiation, easy peasy to do this
in Sage. Note that later we pick h such that h_inv exists
"""
# psi: K -> K
def psi(u):
    return u^h

# psi^-1: K -> K
def psi_inv(u):
    return u^h_inv

"""
The L functions can be computed directly from M, k which
we are given in output.txt
"""
def L1(x):
    return M1 * x + k1

def L1_inv(x):
    return M1.inverse() * (x - k1)

def L2(x):
    return M2 * x + k2

def L2_inv(x):
    return M2.inverse() * (x - k2)


"""
Putting this all together we can write the excryption function
This is the function f given at the top of page 2

f: K -> K
"""
def encrypt(x):
    tmp = L1(x)
    tmp = phi_inv(tmp)
    tmp = psi(tmp)
    tmp = phi(tmp)
    return L2(tmp)

"""
We're not given this, but simply performing the inverse of each
step backwards from encrypt() gives a valid decrypt function :)
"""
def decrypt(y):
    tmp = L2_inv(y)
    tmp = phi_inv(tmp)
    tmp = psi_inv(tmp)
    tmp = phi(tmp)
    return L1_inv(tmp)
    

"""
Now all we have to do is extract the private key and flag 
from the file and use our functions

Private key is made from (h, M1, k1, M2, k2). We are given
M1, M2, k1, k2 which we can extract from our data
"""
M1 = file_to_sage(66, 'M1: ')
M1 = Matrix(F, M1)
k1 = file_to_sage(67, 'k1: ')
k1 = vector(F, k1)

M2 = file_to_sage(69, 'M2: ')
M2 = Matrix(F, M2)
k2 = file_to_sage(70, 'k2: ')
k2 = vector(F, k2)

"""
The flag is split between two lines which are encrypted 
and decrypted respectively. Lets grab the two pieces.
"""
flag_encrypted = file_to_sage(76, 'an encryption: ')
flag_encrypted = vector(F, flag_encrypted)

flag_decrypted = file_to_sage(77, 'a decryption: ')
flag_decrypted = vector(F, flag_decrypted)


"""
The final piece of the puzzle is to find \theta. We don't
know it, but we know there aren't that many options as we 
need h_inv to exist. We can simply loop through and check 
all valid theta.
"""

q = 2^8
for theta in range(2,n):
    h = q^theta + 1
    """
    h inverse must exist, so we must have that h is coprime 
    to the group order
    """
    if gcd(h, q^n - 1) != 1:
        continue

    print(f'Guessing theta = {theta}')
    h_inv = inverse_mod(h, q^n - 1)

    k = decrypt(flag_encrypted)
    k_xor_flag = encrypt(flag_decrypted)

    k_bytes = from_V_to_bytes(k)
    k_xor_flag_bytes = from_V_to_bytes(k_xor_flag)

    print(xor_bytes(k_bytes, k_xor_flag_bytes))
    #  b'CHTB{Imai_and_Matsumoto_play_with_multivariate_cryptography}''
```

### Flag

`CHTB{Imai_and_Matsumoto_play_with_multivariate_cryptography}`
