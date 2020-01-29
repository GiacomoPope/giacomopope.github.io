# Infant RSA

This was the RSA challenge from the recent security fest CTF. 

## Challenge

The challenge was given through a text file containing the following information

```
sage: n
808493201253189889201870335543001135601554189565265515581299663310211777902538379504356224725568544299684762515298676864780234841305269234586977253698801983902702103720999490643296577224887200359679776298145742186594264184012564477263982070542179129719002846743110253588184709450192861516287258530229754571
sage: e1
1761208343503953843502754832483387890309882905016316362547159951176446446095631394250857857055597269706126624665037550324
sage: e2
855093981351105496599755851929196798921968934195328015580099609660702808256223761150292012944728436937787478856194680752
sage: pow(2*p + 3*q, e1, n)
621044266147023849688712506961435765257491308385958611483509212618354776698754113885283380553472029250381909907101400049593093179868197375351718991759160964170206380464029283789532602060341104218687078771319613484987463843848774508968091261333459191715433931164437366476062407396306790590847798240200479849
sage: pow(5*p + 7*q, e2, n)
90998067941541899284683557333640940567809187562555395049596011163797067246907962672557779206183953599317295527901879872677690677734228027852200315412211302749650000923216358820727388855976845209110338837949758874186131529586510244661623437225211502919198181138808456630705718961082655889960517754937606840
sage: pow(m, 65537, n)
350737073191287706245279077094231979383427790754965854345553308198026655242414098616160740809345373227967386631019166444200059217617767145638212921332649998355366471855362243913815961350928202877514312334160636449875324797999398782867956099814177529874805245928396620574131989901122269013123245826472838285
```

## Method

The trick with this challenge is to solve for `p` and `q` using the relationships

<img src="https://latex.codecogs.com/svg.latex?\begin{align*}&space;c_1&space;&=&space;(2p&space;&plus;&space;3q)^{e_1}&space;\mod&space;n&space;\\&space;c_2&space;&=&space;(5p&space;&plus;&space;7q)^{e_2}&space;\mod&space;n&space;\end{align*}">

As the modulus `n = pq`, the binomial expansion of these powers is simply

<img src="https://latex.codecogs.com/svg.latex?\begin{align*}&space;c_1&space;&=&space;(2p)^{e_1}&space;&plus;&space;(3q)^{e_1}&space;\mod&space;n&space;\\&space;c_2&space;&=&space;(5p)^{e_2}&space;&plus;&space;(7q)^{e_2}&space;\mod&space;n&space;\end{align*}">

as all cross terms will contain a `pq = n`, and `xn mod n = 0`. If we take each of these expressions to the appropriate powers we obtain

<img src="https://latex.codecogs.com/svg.latex?\begin{align*}&space;c_1^{e_2}&space;&=&space;(2p)^{e_1&space;e_2}&space;&plus;&space;(3q)^{e_1&space;e_2}&space;\mod&space;n&space;\\&space;c_2^{e_1}&space;&=&space;(5p)^{e_1&space;e_2}&space;&plus;&space;(7q)^{e_1&space;e_2}&space;\mod&space;n&space;\end{align*}">

We want to find a way to elimintate p and write q in terms of the known values `c1,c2,e1,e2,n`. We can do this by making the coefficient for `p` the same in both lines to obtain: 

<img src="https://latex.codecogs.com/svg.latex?\begin{align*}&space;c_1^{e_2}&space;\cdot&space;5^{e_1&space;e_2}&space;&=&space;(10p)^{e_1&space;e_2}&space;&plus;&space;(15q)^{e_1&space;e_2}&space;\mod&space;n&space;\\&space;c_2^{e_1}&space;\cdot&space;2^{e_1&space;e_2}&space;&=&space;(10p)^{e_1&space;e_2}&space;&plus;&space;(14q)^{e_1&space;e_2}&space;\mod&space;n&space;\end{align*}">

We now simply take the difference between these two expressions to obtain

<img src="https://latex.codecogs.com/svg.latex?\begin{align*}&space;c_1^{e_2}&space;\cdot&space;5^{e_1&space;e_2}&space;-&space;c_2^{e_1}&space;\cdot&space;2^{e_1&space;e_2}&space;=&space;q^{e_1&space;e_2}&space;\mod&space;n&space;\\&space;\end{align*}">

The value of `q` can then be found by calculating the greatest common divisor of this expression and the modulus `n`

<img src="https://latex.codecogs.com/svg.latex?\begin{align*}&space;q&space;=&space;gcd(n,&space;c_1^{e_2}&space;\cdot&space;5^{e_1&space;e_2}&space;-&space;c_2^{e_1}&space;\cdot&space;2^{e_1&space;e_2})&space;\\&space;\end{align*}">

From here the rest of the challenge is a simple implementaton of cracking RSA where `p,q,e` are all known. This results in the flag `sctf{dr4_m1g_b4kl4ng3s}`

## Python Implementation

```python
import math
from Crypto.Util.number import inverse

# RSA Data

n = 808493201253189889201870335543001135601554189565265515581299663310211777902538379504356224725568544299684762515298676864780234841305269234586977253698801983902702103720999490643296577224887200359679776298145742186594264184012564477263982070542179129719002846743110253588184709450192861516287258530229754571
e = 65537
c = 350737073191287706245279077094231979383427790754965854345553308198026655242414098616160740809345373227967386631019166444200059217617767145638212921332649998355366471855362243913815961350928202877514312334160636449875324797999398782867956099814177529874805245928396620574131989901122269013123245826472838285

# Puzzle Data

e1 = 1761208343503953843502754832483387890309882905016316362547159951176446446095631394250857857055597269706126624665037550324
e2 = 855093981351105496599755851929196798921968934195328015580099609660702808256223761150292012944728436937787478856194680752
c1 = 621044266147023849688712506961435765257491308385958611483509212618354776698754113885283380553472029250381909907101400049593093179868197375351718991759160964170206380464029283789532602060341104218687078771319613484987463843848774508968091261333459191715433931164437366476062407396306790590847798240200479849
c2 = 90998067941541899284683557333640940567809187562555395049596011163797067246907962672557779206183953599317295527901879872677690677734228027852200315412211302749650000923216358820727388855976845209110338837949758874186131529586510244661623437225211502919198181138808456630705718961082655889960517754937606840

#Solve for p,q

q = math.gcd(n, pow(c1, e2, n)*pow(5,e1*e2,n) - pow(c2, e1, n)*pow(2,e1*e2,n))
p = n // q

# Standard RSA

phi = (p-1)*(q-1)
d = inverse(e,phi)
m = pow(c,d,n)
print(bytes.fromhex(format(m,'x'))[:23].decode('utf-8'))

# >> sctf{dr4_m1g_b4kl4ng3s}
```