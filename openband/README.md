# Open Band, Open Problem

> This blogpost was originally posted on [CryptoHack](https://blog.cryptohack.org/openband). 

Last week, CryptoHack played in CryptoCTF as a big team and managed to grab second place. We shared a [write up](https://blog.cryptohack.org/cryptoctf2020) of the challenges we solved soon after the competition ended. Of all the challenges we saw, two of them managed to stump us during the 24 hours that the CTF was running for.

One of the unsolved challenges was Chilli. During the CTF, it was only solved by [Hellman](https://affine.group), who incidentally also took first place. The aim of the challenge was to find a collision for a hash function, and the solution is the subject of [this paper](https://eprint.iacr.org/2009/376.pdf).

The other challenge was called Open Band, and unlike Chilli, as a team, we sunk a lot of time into trying to solve it. The main reason we kept going was that for a lot of the competition, we felt *really close* to the solve. Right up until the last few minutes of the CTF, I thought we were going to grab the flag. However, it's now a week later, and we're still no closer to understanding how to solve this challenge than we were during the competition.

It's worth saying that during the last hour of the competition this challenge was solved by [CTD Elite](https://ctftime.org/team/34465), but the more I look into this challenge, the less I understand how they were able to.

I want to write this blog post for two reasons. The first being that almost every write-up is a victory story. As a result, the struggles a team goes through during a CTF never make it into the write-up. I thought it would be insightful and encouraging, for people to read a blog post full of both good and bad ideas. To paint a picture of what trying to solve a challenge looks like, without the clarity of post-solve hindsight.

The second reason is I'm getting close to feeling like this challenge is impossible, so I'm playing the classic card of telling the internet something is impossible, and waiting to be corrected.

## The Challenge

> Open Band Ring (OBR) during the wedding ceremony. Your mission is to find the flag using the given OBR function.

```
nc 05.cr.yp.toc.tf 37711
```

### What we know

#### Connecting

Connecting to the server, we are given the following menu:

```
------------------------------------------------------------------------
|        .: Open Band Ring (OBR) during the wedding ceremony :.        |
|    Your mission is to find the flag using the given OBR function.    |
|    In each step you can request obr() value for some random or       |
|    provided integer by yours.                                        |
------------------------------------------------------------------------
| Options:
|   [O]BR function
|   [G]et the obr value!
|   [C]ipher flag  
|   [E]ncryptio function
|   [F]eeling lucky  
|   [P]rint n
|   [Q]uit
```

Let's go through the options and see what we are working with.

#### The Encrypted Flag

Sending option `E` gives us the source of the encryption function:

```python
def encrypt(msg, secret_func, n):
    return pow(secret_func(bytes_to_long(msg), n), 65537, n)
```

Sending `C` gives us the output value of this function:

```python
encrypt(FLAG, secret_func, n) = 287076550566531177504474856702961426217374524796258175288644367804598358769707444614570125137603805670832312669899814741087068193546558223915623243101603509474507745421944594709409998
```

We see that an RSA encryption is performed on the integer `secret_func(bytes_to_long(FLAG), n)`, using the exponent `65537`, and a modulus `n`. If we can break this encryption, we can obtain the numerical value of `secret_func(bytes_to_long(FLAG), n)`.

Sending option `P` to the server, we are given the value of the modulus

```python
n = 689707807395625229628721449564122367957565117789481990602260353362159734588373136707976678180690717110951286561128386474155976818347737307507904611442523943760053142435507972061487817
```

On every connection, `n` is different and has a wide range in possible bit values. Looking through what we're given over a handful of connections, we see that `350 < n.bit_length() < 1000`.

Furthermore, `n` is a highly composite number. (I only show one value for `n` here, but the structure is approximately the same for each connection: many moderately sized primes).

```py
sage: n = 68970780739562522962872144956412236795756511778948199060226035336215973458837313670797667818069071711095128656
....: 1128386474155976818347737307507904611442523943760053142435507972061487817
sage: ecm.factor(n)
[135786245801, 10662448280749, 919671279638483, 10270318983645829, 20592539075195539, 20592539075195539, 145008305564735377, 256771998283195459, 2638162579507812341, 597999741257069306957, 2024757324115154976929]
```

As we can factor `n`, we can easily undo the RSA part of the encryption

```py
n = 689707807395625229628721449564122367957565117789481990602260353362159734588373136707976678180690717110951286561128386474155976818347737307507904611442523943760053142435507972061487817
c = 287076550566531177504474856702961426217374524796258175288644367804598358769707444614570125137603805670832312669899814741087068193546558223915623243101603509474507745421944594709409998
e = 65537
phi = euler_phi(n)
d = inverse_mod(e,phi)
secret_flag = pow(c,d,n)
print(secret_flag)
# 576129413395188424457822230232823822361376862859639978677712224140705865625899503562751001357933628838544021623029252126053108517584999498465165372384392913992511722629759289936122666
```

To solve the challenge, we must learn what the  **inverse** of `secret_func(FLAG, n)` is.


#### OBR Function and Secret Function

The remaining options: `{O, G, F}` correspond to an interaction with the `obr(x)`.

By sending `O`, we are given the source of the OBR function


```py
def obr(secret_func, n): # very very slow :(
    i, res = 1, 0
    while i <= n:
        if gcd(i, n) == i:
            res += secret_func(i, n)
        i += 1
    return res
```

We see the classic CTF function which has been purposefully implemented badly, and part of the challenge is rewriting it so that it behaves reasonably with a large input. Looking through, we see that the return value `res` is added to by  `secret_func(i, n)`, whenever `i` divides the input `n`. This means rather than looping over the whole of `n`, we should compute the divisors of the input integer and then loop through those.

```python
def obr_fast(secret_func, n):
    res = 0
    ds = divisors(n)
    for d in ds:
        res += secret_func(d, n)
    return res
```

Here, we're using the inbuilt sage function `divisors()`. Note that we cannot test this function locally, as we still have no knowledge of `secret_func`.

Sending the option `G` to the server gives us the following question:

```
Do you want to provide desired integer as `n'? [Y]es [N]o
```

If we send `N` we are told

```
| Calculation of `obr' is time consuming, please wait...
```

followed by the output

```
obr(secret_func, 765345698040090228792773207338789407568090237674331154131788004776927480496362451900894517677132976247718801488879678453754351365816422191418272030646841844348260700382856474912166814226266797813405359164057420123790004775545803613889263334293157264264061529037070183777029251155067737478103347559089533806585165287370529956951511343778724338551828766760782598116378903324433579965487899) = 29432049607146558842365734145738278864116394931350343763190332775599191397249380798216716458371133243119164574439261011717857623888504783698539592123345545624979619971159566594991180622144474204162108749223435533435702640792682895311454209010411566566170444070725717061062296977965720493254303528435159518904686501166498767416696352593361666997807601023315487995224882192580994666639659174435
```

This seems to be generating some very large integer and running it again, we get a new input/output pair

```
| obr(secret_func, 24721972020984040955384728437795668322206399343452336266436493794876878520844546347613624034747520216352313646969981165191126541376496559752134661901061259572190127168519083232249076421858413268947467387981850952171753997798001270252793128261065263882527101623934435930541426455743111702915066346716204629082962802159043006467976569607246450857) = 456519430497022508459990923704811976083836444186205204309298356153460232076234659989802606685200770006684422045988625343835283660399041711916460700973521222418723595600233701928501251571346492093890318627121741381279123225221047527700577332478749869860134517967499646832384067300196205004583723635416567466401772769131889305973236868794490661058744
```

suggesting the integer picked is random.

If we instead answer `Y` to the option `G` we are given the following prompt

```
enter your integer `n' as (p1_, a_1), ..., (p_k, a_k) where p_i's are distinct prime factors of n and a_i's are their exponents!
```

Sending `1859 = 11*13^2` (for example) the server calculates

```
(11,1), (13,2)
| obr(secret_func, 1859) = 7940
```

We will discuss this more later. The final option to consider is `[F]eeling lucky`. Sending `F` to the server, we are given the prompt

```
| Can you find and send the secret_func(408293452197165374954264958167335998071988562830779438670682790885782139176184139506333005716330896032069536142059095662398249609848767724045719)? [Y]es or [N]o
```

If we answer `N`, we are bought back to the menu. Sending option `F` again, we are given

```
| Can you find and send the secret_func(89095858823180990488256254648197349390652793883004928184441975895072915567794636798608058308520551787890300075829830319753)? [Y]es or [N]o
```

and we see the input value has changed. Sending `Y` as an answer, we are prompted

```
| please send the result:
```

making a guess `123` we are told

```
| Sorry, your answer in NOT correct! return to main menu!!
```

If we return to `F` after getting the answer wrong, we see that the integer `x` has again changed.

#### Summary

- The flag is encrypted twice, first with an unknown `secret_func`, and then with RSA-like encryption.
- The RSA encryption is performed with a highly composite public key `n` which changes on every connection. **We can break this stage**.
- We have access to a function called `obr(x)` which will compute a value for a given integer `x` once we supply it with the prime factorisation.
- The function `obr(x)` returns the sum over all divisors `d` of `secret_func(d,x)`
- We have the `Feeling Lucky` option, which asked "what is the result of `secret_func(x,n)`" for the public modulus `n` and random(?) integer `x`. We are not told what will happen if we get this correct.

#### Questions

- What does answering "Feeling Lucky" do?
- Can we find the exact form of `secret_func` from `obr(n)`?
- What is the use of asking for a random number from `obr(n)`?

## Searching for Secrets

Let us consider the `obr(x)` function in more detail. In fact, before considering the `obr(x)` function, let's go over some background.

### Möbius inversion

It turns out sums over functions of divisors is something mathematicians have considered in general.

Möbius, a German mathematician -- famous for his mind-bending [Möbius strip](https://en.wikipedia.org/wiki/Möbius_strip) -- considered functions of the form

$$
F(n) = \sum_{d | n} f(d)
$$

Where $d$ are the divisors of $n$ (looking familiar?). He showed that if the above function holds for all integers $n$, we can perform a **Möbius inversion** to compute the value of $f(n)$ for all $n$

$$
\begin{align*}
f(n) &= \sum_{d | n} \mu(d) F \left( \frac{n}{d} \right) \\ &= \sum_{d | n} \mu\left( \frac{n}{d} \right) F(d)
\end{align*}
$$

where this new function $\mu(x)$ is called the [Möbius function](https://en.wikipedia.org/wiki/Möbius_function), which takes on three different values:

- $\mu(x) = 1$ if $x$ is a square-free positive integer with an even number of prime factors.
- $\mu(x) = -1$ if $x$ is a square-free positive integer with an odd number of prime factors.
- $\mu(x) = 0$ if $x$ has a squared prime factor.

As a quick aside, let's consider a function cryptographers are more used to. Euler's totient function $\phi(n)$ counts the number of integers coprime to $n$. From this, we can write

$$
n = \sum_{d | n} \phi(d)
$$

Which means through performing a Möbius inversion, one can write a formula for the totient function

$$
\phi(n) = \sum_{d | n} \mu(d) \frac{n}{d}
$$

Don't get hopeful that this will help you with your RSA challenges, though! Note that to compute the right-hand side, you don't only need the factors of $n$, but you additionally need all the divisors. You also need the value of $\mu(d)$, so no short cuts here. This doesn't take away from this as a beautiful piece of maths, though. If you find this interesting, I recommend [this resource](https://www.mtholyoke.edu/~robinson/reu/reu05/rdineva1.pdf).

### Back to the challenge

In this challenge, we are asked to compute

$$
f(x, N) = \; ?
$$

with known $\{x,N\}$ but the form of the function $f$ is unknown.

We have access to a function on the server which computes

$$
F(n) = \sum_{d | n} f(d,n)
$$

This, together with the suggestive name of the challenge, seems to suggest a Möbius transformation is the key to finding the value of $f(x,N)$.

We have a problem here, though. The secret function $f(x,n)$ doesn't only take values from the divisors, but also the input $n$ too. If we naively try to perform a Möbius transformation, we would obtain the expression

$$
f(x, N) = \sum_{d | x} \mu\left(\frac{x}{d}\right) F(d)
$$

However, this seems like an ill-defined relationship. On the LHS of this equation, we have two variables $x, N$, but we know that the function $F(x)$ (`obr(x)` on the server) takes only one. How can we perform the inversion if we have irregular dependences on either side of the equation?

While looking for more information about applications of Möbius inversions, Joachim found [this resource](http://web.math.ucsb.edu/~padraic/ucsb_2014_15/math_116_s2015/math_116_s2015_lecture4.pdf). Our hopes were raised when we saw on page 21, a Möbius inversion of a function just like ours: $f(d,n)$. However, what is actually shown is that for the function they consider, they can prove that $f(d,n) = f(d,d) = \tilde{f}(d)$, and so really it's just the standard Möbius for one variable in disguise.

As such, it seems impossible to recover $f(x,N)$ with a naive Möbius inversion. It was here that we got totally stuck during the competition.

### An open band of failure

As promised, rather than just talk about what worked, I want to talk about some of the things we tried, and why we hoped they would work, and why they didn't.

#### Baby Steps

First things first, let's make sure we can actually implement the Möbius inversion.

Lets take some dummy function $f(x) = x^2 + 3$ and invent some function

$$
F(n) = \sum_{d|n} f(d)
$$

Let us imagine that we have access to `F(n)` for all $n$, but that we don't know the form of $f(x)$. Let's try implementing the inversion.

```python
def secret_func(x):
    return x^2 + 3

def dummy_obr(dummy_function, n):
    res = 0
    ds = divisors(n)
    for d in ds:
        res += secret_func(d)
    return res

def dummy_mobius_inversion(n):
    res = 0
    ds = divisors(n)
    for d in ds:
        res += moebius(d) * dummy_obr(secret_func, n//d)
    return res

for _ in range(100):
    x = ZZ.random_element(0,10^5)
    assert secret_func(x) == dummy_mobius_inversion(x)
```

Where we are using SageMath so that `moebius` and `divisors` can be found with inbuilt functions.

Running this script, we get no errors, so it seems like it's looking good.

Okay, now lets do something easy and dumb and give a new variable to the function: $f(x, n) = x^3 + 3 \mod n$ and try an inversion again

```python
def secret_func(x, n):
    return (x^2 + 3) % n

def dummy_obr(dummy_function, n):
    res = 0
    ds = divisors(n)
    for d in ds:
        res += secret_func(d, n)
    return res

def dummy_mobius_inversion(n):
    res = 0
    ds = divisors(n)
    for d in ds:
        res += moebius(d) * dummy_obr(secret_func, n//d)
    return res

for _ in range(100):
    x = ZZ.random_element(0,10^5)
    y = ZZ.random_element(0,10^5)
    assert secret_func(x, y) == dummy_mobius_inversion(x)
```

```
  File "dummy.sage", line 27, in <module>
    assert secret_func(x, y) == dummy_mobius_inversion(x)
AssertionError
```

Unsurprisingly, this doesn't work, and plainly we can see why. How is `dummy_mobius_inversion(x)` ever going to reproduce `f(x,y)` without any knowledge of `y`. The input into `f(d,x)` in the `obr` function is always just the input `x`. It seems that if we ever want this to work, there will have to be a relationship between `x,y`.

So our first thought was, if $n$ can't be a variable, what if we were being fooled, and $f(x,n)$ was in-fact not dependent on $n$ at all??

We can check this on the server. Connecting twice, we get two pairs of data `(enc_1, n_1)` and `(enc_2, n_2)` for the encrypted flag and public modulus. As we can factor `n`, we can find the value of `secret_func(FLAG, n)`. The modulus `n` is different on each connection, so if `secret_func` is not dependent on `n` then the decrypted value would be the same!

Turns out... they're not. From this, we are left with two conclusions:

- The flag is randomly padded, and we may still have $f(x,n) = f(x)$
- `secret_func` depends on the public modulus, and the naive inversion just won't work

We can check the first point by trying to pass the feeling lucky option. Performing an inversion through the server, we find that we fail this step. It seems like we can't ignore $n$.


### Möbius doubts

With the inversion not working, after a few hours of playing around, we came to the conclusion that the inversion was the wrong method and we needed a different way to crack it. Solving feeling lucky seemed impossible from `obr`, and so we turned to numerology. We gave `obr` a series of inputs and tried out best to learn what for `obr` spat out as a function of `x` and tried to learn something about the secret function this way.

We wrote a quick script to grab obr values, and we were able to spot that

$$
F(p^k) = (k+1)p^k -1
$$

which we checked for

```python
import os
os.environ["PWNLIB_NOTERM"] = "True"
from pwn import *

def get_obr(n):
    r.sendline('G')
    r.recvuntil('[N]o\n')
    r.sendline('Y')
    r.recvuntil('eir exponents!\n')
    factors = list(factor(n))
    send_factors = ', '.join(str(i) for i in factors)
    print(send_factors)
    r.sendline(send_factors)
    data = r.recvuntil(b'|  [Q]uit')
    print(data)
    x = int(data.decode().split()[4].strip())
    return x

r = remote('05.cr.yp.toc.tf', 37711, level='debug')
r.recvuntil(b'[Q]uit\n')

ps = [2,3,5,7,11,13]
ks = [1,2,3,4,5]

for p in ps:
  for k in ks:
    assert get_obr(p^k) == (k+1)*(p^k) - 1
```

Our hope was that by narrowing down $F(n)$, we might find that it was some known function and that we could determine $f(x,n)$ this way. However, when we allow $F(p\*q)$, for distinct primes $p,q$, we were unable to find a closed-form for the expression of $F(p\*q)$.

We also spent some time chasing the Möbius clue in other directions. We thought that maybe $F(n)$ was some well-known function for the Möbius strip, or that there was a function $f(x,y)$ which computed something interesting about the Möbius strip. Maybe all we have to do is guess the function? Again, we didn't find anything that fit the pattern.

Another fun trick with problems like this is to look at the first 10 or so values and check [OEIS](https://oeis.org). We can use the script above to find

```python
sols = [get_obr(i) for i in range(2,25)]
print(sols)
# [3, 5, 11, 9, 18, 13, 31, 26, 26, 21, 56, 25, 46, 42, 79, 33, 87, 37, 102, 73, 58, 45, 156]
```

but searching these values came back with nothing. Taking only prime inputs, we get the OEIS sequence [A076274](https://oeis.org/A076274) , which is simply integers $n = 2p - 1$, which we knew already from the above, more general relationship.

### Game Over

Eventually, our 24 hours were up, and the challenge was left with a single solution. Hellman dropped the Chilli solution into the IRC and the secret function we had been searching for was leaked

```python
def secret_func(s, n):
    return n - pow(s, 38167, n)
```

Looking at it now, we can see using numerology to guess its form was hopeless.

We see that this function is trivial to invert once the factorisation was known, so all of the challenge was finding exactly what `secret_func` was.

It turns out, you obtained the source for `secret_func` by correctly answering `[F]eeling Lucky`. I think if this had been told explicitly in the challenge it would have helped keep us from rabbit holes, but we probably should have realised its presence on the server was enough of a clue to know it was important.

We'll finish this blog post with a write-up of the solution with an enormous missing step, and then make a few comments about `[F]eeling Lucky`, and how everything points to the solution (if there is one) being some generalised Möbius transformation.


## The Solution

With the competition over, and the secret function leaked, let's summarise how this problem was expected to be solved.

We would begin by connecting to the server and grabbing the values of the encrypted flag and the public modulus.

Here the missing step comes in, in which through access to the server, the `obr(x)` function and possibly a whole range of other clever insights, we can correctly answer option `F`. Getting `F` correct, we would get the following reply from the server

```
| Great! only one step to flag!!!
| You have unlocked the secret_func successfully, now try to find flag!!
```

```python
def secret_func(s, n):
    return n - pow(s, 38167, n)
```

Armed with the secret function, it is now obvious to find the inverse. The number `38167` is prime, and so this is simply another round of RSA encryption to break. (I mention it's prime only in that we are more likely to find the inverse mod $\phi$).

With knowledge of `secret_func`, the full solution to the challenge is fairly simple.

#### Implementation

```python
from Crypto.Util.number import long_to_bytes

n = 689707807395625229628721449564122367957565117789481990602260353362159734588373136707976678180690717110951286561128386474155976818347737307507904611442523943760053142435507972061487817
c = 287076550566531177504474856702961426217374524796258175288644367804598358769707444614570125137603805670832312669899814741087068193546558223915623243101603509474507745421944594709409998
e = 65537
phi = euler_phi(n)
d = inverse_mod(e,phi)
secret_flag = pow(c,d,n)

secret_e = 38167
secret_d = inverse_mod(secret_e,phi)
enc_flag = n - secret_flag
flag = pow(enc_flag, secret_d, n)
print(long_to_bytes(flag))
# b'CCTF{W3_likE_M0bIu5_B4nD_aZ_W3dD!n9_rInG}'
```

### Flag

`CCTF{W3_likE_M0bIu5_B4nD_aZ_W3dD!n9_rInG}`

## Feeling Lucky?

### Lucky numbers

So how do we solve the feeling lucky challenge? Let's go back over what we know, with hindsight and try to see something interesting.

The obr function looks like

```python
def obr_fast(secret_func, n):
    res = 0
    ds = divisors(n)
    for d in ds:
        res += secret_func(d, n)
    return res
```

and we see the second argument of `secret_func` is the integer we supply. This means is we want to gain information about `f(x,N)`, we will only get this if the integer we send to `obr` is the modulus itself

$$
F(N) = \sum_{d | N} f(d, N)
$$

But this is only close to a meaningful thing to look at if the `lucky` variable we must evaluate is the modulus itself. I would be surprised if this is an "attack the server until you get a good lucky number", especially as there was originally a POW at the beginning of the challenge. So I won't follow this reasoning any further.

We thought that maybe if the `lucky` integer was a divisor of the public integer, we might be able to manipulate the output.

I grabbed a session with the server, and looked at `gcd(lucky, N)` for many `lucky`, but found they were always coprime.

While I was grabbing data, I also looked at the `lucky` ints themselves. I found that they were highly composite, like the modulus. I collected all their factors, from multiple integers and found

```
[+] modulus: 3589722944932308858871170909196722474077045120161952856605164336420747607551041134638113547498712400134211107085498968616086761393163387993937782460208448506877427271031
Modulus factors: [3241498788503, 15140930640271, 560317173642409, 560317173642409, 713289895746721, 611287529857749691, 978865507047079763, 80938153356958712333, 2351230690589197064617, 2868213415906366979299]
count of all lucky factors: 9
set of lucky factors: 7
gcd of modulus and lucky: 1
count of all lucky factors: 20
set of lucky factors: 14
gcd of modulus and lucky: 1
count of all lucky factors: 30
set of lucky factors: 22
gcd of modulus and lucky: 1
count of all lucky factors: 40
set of lucky factors: 29
gcd of modulus and lucky: 1

...

count of all lucky factors: 385
set of lucky factors: 325
gcd of modulus and lucky: 1
```

There seems to be a non-trivial overlap of their common factors... I thought this might be interesting, but I didn't get any further with this. Even if there was something to the shared factors, there's still seemed to WAY too many to imagine having some kind of lookup table for `obr` for all the factors/divisors of `lucky`. I include this here, in case I'm missing something huge someone else can see.

Part of me thinks that there's some kind of "Chinese remainder theorem" going on, where you compute obr for all the prime factors of `lucky` or `n`, or both... Maybe there's some way to construct $f(x,N)$ from a bunch of smaller pieces. The problem I have with this hunch is that $f(x,n)$ isn't multiplicative or additive. In fact, I haven't found a clever way in any form to say $f(x \cdot y) = f(x,n) \cdot f(y, n)$. It's even harder to imagine doing something clever with some prime factor of $n$.

### Hindsight insight

With the form of the secret function, maybe we can write down the `obr` function in a more illuminating way.

We know that

$$
F(n) = \sum_{d | n} \left[ n - (d^{e} \mod n) \right]
$$

We now see why the case for $n = p^k$ was tractable. All divisors will be $p^i$ for $i \in \{0,1,\ldots,k\}$ and so the sum becomes

$$
\begin{align*}
F(p^k) &= p^k - (1 \mod p^k)  \\
&+ p^k - (p^1 \mod p^k) \\
&+ \ldots \\
&+ p^k - (p^k \mod p^k) \\
&= (p^k - 1) + kp^k
\end{align*}
$$

where we have used that $p^x \mod p^k = 0$.

This also shows how it was hopeless to try and get data about $n = p*q$ for distinct primes.

### So what's the solution?

In short, we have no idea. I spent a while playing with the idea that maybe the challenge was broken. If the `obr` function had been

```python
def obr_fast(secret_func, n):
    global N
    res = 0
    ds = divisors(n)
    for d in ds:
        res += secret_func(d, N)
    return res
```

where the secret function was computed with some global value, instead of the largest divisor, we could have solved the challenge

```python
# small dummy variables
N = 21298379823748923748
lucky = 982789734943820

def secret_func(s):
    global N
    return N - power_mod(s, 38167, N)

def obr_fast(secret_func, n):
    res = 0
    ds = divisors(n)
    for d in ds:
        res += secret_func(d)
    return res

def dummy_mobius_inversion(n):
    res = 0
    ds = divisors(n)
    for d in ds:
        res += moebius(d) * obr_fast(secret_func, n//d)
    return res

assert secret_func(lucky) == dummy_mobius_inversion(lucky)
```

When I thought about it this way (ignoring another team had solved it) I felt like this was possibly the problem. Just a mistake in python where `n` should have been `N`. The problem I realised was that once you ask for the lucky integer, you can't then query `obr(d)` without either opening a new session or leaving the feeling lucky question. If you open a new session, the public modulus changes and the inversion fails, if you leave the lucky prompt, you have no knowledge of what the next integer will be, so this obviously wasn't the problem.

So I'm left with the conclusion that either the challenge is impossible, or there's some generalisation of the Möbius inversion for this challenge that means $f(x,N)$ is able to be found from $\tilde{F}(d,N)$ which takes as an input the public modulus, the divisors of the lucky number and some clever maths.

I hope that this discussion has been interesting to people have tried, and I hope even more than while reading this, someone spots the way to solve this. I was really hoping for a write-up after the competition ended, but nothing yet.
