# NOT Mordell

> I found one integral point on an elliptic curve, so there's finite number of integral solutions.
>
> This means You can pick from an finite number of primes... right?
>
> special thanks: [https://ctf.cr0wn.uk/challenges#Mordell%20primes-11](https://ctf.cr0wn.uk/challenges#Mordell primes-11)
>
> author:theoldmoon0602

## Disclaimer

I didn't play this CTF, but I was pinged when someone noticed this challenge was based off one I made for UnionCTF. It was a fun challenge, i liked it a lot.

## Solution

This challenge is a standard RSA challenge, where the primes are derived as the $x$-coordinates of two points $Q,R$ on an elliptic curve $E / F_p$ which are related by

$$
\begin{aligned}
P &= (P_x, P_y) \\
Q &= [k]P = (Q_x, Q_y)  \\
R &= [k+1]P = (R_x, R_y) \\
\end{aligned}
$$

and from the challenge, we are given the curve $E$,

$$
E: y^2 = x^3 + ax + b \pmod p
$$

the base point $P$ and the RSA modulus $N = Q_x R_x$ . The important data we need is given by:

```python
p = 13046889097521646369087469608188552207167764240347195472002158820809408567610092324592843361428437763328630003678802379234688335664907752858268976392979073
a = 10043619664651911066883029686766120169131919507076163314397915307085965058341170072938120477911396027902856306859830431800181085603701181775623189478719241
b = 12964455266041997431902182249246681423017590093048617091076729201020090112909200442573801636087298080179764338147888667898243288442212586190171993932442177
N = 22607234899418506929126001268361871457071114354768385952661316782742548112938224795906631400222949082488044126564531809419277303594848211922000498018284382244900831520857366772119155202621331079644609558409672584261968029536525583401488106146231216232578818115404806474812984250682928141729397248414221861387
Px = 11283606203023552880751516189906896934892241360923251780689387054183187410315259518723242477593131979010442607035913952477781391707487688691661703618439980
Py = 12748862750577419812619234165922125135009793011470953429653398381275403229335519006908182956425430354120606424111151410237675942385465833703061487938776991
```

To solve the challenge, we must factor $N$ by finding $Q_x$ or $R_x$.

From the group addition law on $E$ we have that:

$$
R_x = \lambda^2 - Q_x - P_x \pmod p, \qquad \lambda = \frac{Q_y - P_y}{Q_x - P_x}
$$

As $N = Q_x R_x$, we can eliminate $R_x$ and obtain the expression

$$
N = (\lambda^2 - Q_x - P_x) Q_x
$$

We now have two unknowns: $(Q_x, Q_y)$ which we know are related by:

$$
Q_y^2 = Q_x^3 + a Q_x + b \pmod p
$$

To solve this equation, we can then write

$$
f(Q_x) = N - (\lambda^2 - Q_x - P_x) Q_x
$$

and look for roots of $f(Q_x)$. The issue I had when I was trying to solve this was that $Q_y = \sqrt{Q_x^3 + a Q_x + b} \pmod p$ and putting this into sage and looking for roots was just breaking it all.

The trick is to rearrange this polynomial to remove the square root so that SageMath played nicely.

We can do this by:

$$
\begin{aligned}
&N + Q_x(Q_x + P_x) = Q_x \left( \frac{Q_y - P_y}{Q_x - P_x} \right)^2 \\ \\
&\left[ N + Q_x(Q_x + P_x) \right] \left[Q_x - P_x\right]^2 = Q_x \left( Q_y - P_y \right)^2 \\ 
&\left[ N + Q_x(Q_x + P_x) \right] \left[Q_x - P_x\right]^2 = Q_x \left( Q_y^2 - 2 Q_y P_y + P_y^2 \right) \\ 
&\left[ N + Q_x(Q_x + P_x) \right] \left[Q_x - P_x\right]^2 - Q_x( Q_y^2  + P_y^2)= - 2 Q_x Q_y P_y  
\end{aligned}
$$

Now writing

$$
\begin{aligned}
f_1 &= \left[ N + Q_x(Q_x + P_x) \right] \left[Q_x - P_x\right]^2 \\
f_2 &=  Q_x( Q_y^2  + P_y^2)
\end{aligned}
$$

We can square both sides to obtain

$$
(f_1 - f_2)^2 = (2 Q_x Q_y P_y)^2
$$

and find roots of:

$$
\tilde{f}(Q_x) = (f_1 - f_2)^2 - (2 Q_x Q_y P_y)^2 \pmod p
$$

```python
F = GF(p)
R.<Qx> = PolynomialRing(F)

Qy2 = Qx^3 + a*Qx + b

f1 = (N + (Px + Qx)*Qx)*(Qx - Px)^2
f2 = Qx*(Qy2 + Py^2)

sol = (f1 - f2)^2 - (4*Qx^2*Py^2*Qy2)

print(sol.roots())

[(5266647903652352665309561331835186152327627163271331811555419978564191000470060566535428497675116887002541568904535904345037425011015457585262022604897451, 1), (4292528248136861387890911319917455946841411872473250675409509735620572311636407361858881556677385609500178629430025710517411214702704597103005396234440737, 1), (11283606203023552880751516189906896934892241360923251780689387054183187410315259518723242477593131979010442607035913952477781391707487688691661703618439980, 2)]
```

This gives us our factors:

```python
from Crypto.Util.number import long_to_bytes
Qx = 5266647903652352665309561331835186152327627163271331811555419978564191000470060566535428497675116887002541568904535904345037425011015457585262022604897451
assert N % Qx == 0
Rx = N // Qx

c = 15850849981973267982600456876579257471708532525108633915715902825196241000151529259632177065183069032967782114646012018721535909022877307131272587379284451827627191021621449090672315265556221217089055578013603281682705976215360078119427612168005716370941190233189775697324558168779779919848728188151630185987
e = 0x10001
phi = (Qx - 1)*(Rx - 1)
d = inverse_mod(e,phi)
m = pow(c,d,N)
print(long_to_bytes(m))

b'zer0pts{7h4nk_y0u_j4ck_7h4nk_y0u_cr0wn}'
```

## Flag

`zer0pts{7h4nk_y0u_j4ck_7h4nk_y0u_cr0wn}`
