# HackTM

| Challenge  | Category | Points | 
| ------------- | ------------- | -------------: |
|[OLD Times](#OLD-Times) | OSINT | 424 |


# OSINT

## OLD Times 
### 424 Points

>There are rumors that a group of people would like to overthrow the communist party. Therefore, an investigation was initiated under the leadership of Vlaicu Petronel. Be part of this ultra secret investigation, help the militia discover all secret locations and you will be rewarded.

Looking at the given text, the main thing that stands out is the name. A quick google gives [twitter.com/PetronelVlaicu](https://twitter.com/PetronelVlaicu)


There's a few tweets that stand out. A photo which is tagged with another user. 
- [twitter.com/NicolaCeaucescu](https://twitter.com/NicolaCeaucescu)

There's only one person the account follows:
- [twitter.com/nicolaeceausesc](https://twitter.com/nicolaeceausesc)

They have a link in their bio:
- [cinemagia.ro/actori/nicolae-ceausescu-73098/](http://www.cinemagia.ro/actori/nicolae-ceausescu-73098/)

Another tweet tells us that they "love Temple OS"

But I wasnt seeing much to go forward. Using wayback machine, I can look of snapshots of the account and I find a deleted tweet with the string:


`1XhgPI0jpK8TjSMmSQ0z5Ozcu7EIIWhlXYQECJ7hFa20`

This looks hopefull! Base64 against this doesn't produce anything readable, but this [](https://a2x2.github.io/link/) by a2x2 tells use that this b64 is associated to a [Google Doc](https://docs.google.com/document/d/1XhgPI0jpK8TjSMmSQ0z5Ozcu7EIIWhlXYQECJ7hFa20/edit)

One part of the doc stands out more than others:

>The local activity is under control. People seek their daily routine and have no doubts about the party, except for one man: Iovescu Marian - who goes by the name of E4gl3OfFr3ed0m

Googling this leads to a GitHub user with a single repository

- [https://github.com/E4gl3OfFr3ed0m/resistance](https://github.com/E4gl3OfFr3ed0m/resistance)

Now we can go through old commits and look at the deleted data. In a line edit we find the url [http://138.68.67.161:55555/](http://138.68.67.161:55555/)

Accessing this account gives a forbidden response though. Looking deeper, we find an old .php file:

```php
# spread_locations.php
<?php		

  $myfile = fopen("locations.txt", "r") or die("Unable to open file!");		
 $locs = fread($myfile,filesize("locations.txt"));		
 fclose($myfile);		
 $locs = explode("\n",$locs);		

  $reg = $_GET["region"];		
 if($reg < 129 && $reg >= 0){		
   echo "<b>[".$reg."]:</b> ";		
   echo $locs[$reg];		
 }		
 else{		
   echo "<b>Intruder!</b>";		
 }		

?>
```

I wrote a quick python script to get all the locations data:

```py
import requests

locations = []

for x in range(0,129):
	page = requests.get('http://138.68.67.161:55555/spread_locations.php?region=' + str(x))
	loc = page.text.split(' ')
	l = loc[1]
	locations.append(l)

for l in locations:
	print(l)
```

This gives the data

```
22.5277957,47.3561089
22.5497683,47.184652
22.5277957,47.0276192
22.538782,46.8851427
22.5607546,46.6669469
22.5827273,46.508391
22.7365359,47.0051481
22.9342898,47.0500808
23.14303,47.0425947
23.2968386,47.4527737
23.3297976,47.2667225
23.3407839,47.1024545
23.3737429,46.9601776
23.3847292,46.8024828
23.3847292,46.6443244
23.879114,46.6970954
24.2636355,47.6825664
24.8459109,46.7648681
25.1864871,47.7343156
25.351282,46.8475858
24.1317996,47.5715023
24.0439089,47.4156159
23.945032,47.2443522
23.9010867,47.1024545
23.8571414,46.945179
24.3844851,47.5715023
24.5382937,47.4230496
24.615198,47.2741771
24.6921023,47.1398328
24.8019656,46.9826676
24.0988406,47.2145105
24.3075808,47.2592668
24.4723757,47.2890833
25.2304324,47.5863245
25.2633914,47.4081812
25.318323,47.2368934
25.3293093,47.0874959
25.4831179,47.4156159
25.3952273,47.7860133
25.6149539,47.8229089
25.7797488,47.756478
25.8236941,47.6233616
25.7138308,47.5047505
25.5819949,47.3263302
25.7358035,47.2145105
25.9335574,47.072533
25.9994753,46.9376782
26.2192019,47.9996428
26.1862429,47.8892548
26.2301882,47.7047509
26.2521609,47.5789139
26.2851199,47.4230496
26.3400515,47.2890833
26.4609011,47.9481577
26.625696,47.8524065
26.8014773,47.6825664
26.8783816,47.5344284
26.3949832,47.1323592
26.9223269,47.3933087
26.82345,47.2741771
26.4389285,46.9901622
26.6696414,47.0201299
26.8454226,47.1921182
21.8905886,45.7009791
22.1213015,45.7009791
22.3520144,45.7086515
22.5497683,45.723993
22.7914675,45.7316622
23.4286746,45.8006377
24.0878542,45.9001182
24.7909792,45.9383326
25.4281863,46.0451929
25.6149539,46.0756865
25.8017214,46.0833073
25.988489,46.0756865
26.1862429,46.090927
22.3630007,45.5242242
22.3849734,45.3391904
22.406946,45.161297
22.4179324,44.9828465
22.4289187,44.8116333
23.4616335,45.6395623
23.4836062,45.4549076
23.5165652,45.2541805
23.5495242,45.0915349
23.5495242,44.9206461
24.1208132,45.7469975
24.9008425,45.7776553
24.0988406,45.5780782
24.1317996,45.3469122
24.1647585,45.1458017
24.1757449,45.0216875
24.9997195,45.6626015
25.0107058,45.4703187
25.0107058,45.2928371
25.0326785,45.1225508
24.5712527,45.5934555
24.7030886,45.8082963
24.3734988,45.7316622
25.4281863,45.8848251
25.4611453,45.6779557
25.4941042,45.4934274
25.5380496,45.3005653
25.5600222,45.1690431
25.7907351,45.2000169
26.054407,45.246446
26.3070925,45.2773776
25.6698855,45.6626015
25.8566531,45.723993
27.4826296,46.1594571
27.3178347,46.2203012
27.1090945,46.2658901
26.9333132,46.2203012
26.7795046,46.1442356
26.7026003,45.9765207
26.8783816,45.8848251
27.0651492,45.8618775
27.2629031,45.8465739
27.4496707,45.7853172
27.526575,45.6702792
27.5705203,45.6088287
27.5046023,45.4857255
27.4167117,45.4163615
27.2738894,45.4009357
27.1200808,45.3623528
26.9223269,45.3855057
26.7685183,45.5319208
23.9230593,46.410005
25.4941042,46.5386279
```

These coordinates are all too close to be interesting on a map, but we can plot them all on a plane using [Desmos](https://www.desmos.com/)

![Plot of flag](https://github.com/jack4818/CTF/blob/master/HackTM/plot.png "Plot of flag")

Which gives us the flag!

HackTM{HARDTIMES}
