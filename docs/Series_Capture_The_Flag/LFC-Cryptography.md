# Learning from the CTF : Cryptography

> This post (Work in Progress) lists the tips and tricks while doing Cryptography challenges during various CTF’s.

* Caesar cipher and substitution cipher can be solved by using Cryptool 1. Just check the Analysis option, there’s analysis for Symmetric Key,Asymmetric Key, Hash and others. Otherwise, a good website to solve substitution cipher is  [Quipqiup](http://quipqiup.com/). Ceaser cipher good website is [Caesar cipher decryption tool](https://www.xarg.org/tools/caesar-cipher/)

* If you get some text atleast few paragraphs and some random numbers as (1, 9, 4) (4, 2, 8) (4, 8, 3) (7, 1, 5) (8, 10, 1), it might mean (Paragraph, Line, Word). 

* If you get a poem followed by some numbers and ciphertext, probably it's [Poem Code](https://en.wikipedia.org/wiki/Poem_code) The poem code is a simple, and insecure, cryptographic method which was used by SOE to communicate with their agents in Nazi-occupied Europe. The method works by the sender and receiver pre-arranging a poem to use.

* If you get some ciphertext encrypted by XOR, [xortool](https://github.com/hellman/xortool). It can help you to find the key length and the key.

* All ciphers listed at [Cipher Tools](http://rumkin.com/tools/cipher/)

* If we have a "3845281945283805284526053525260547380516453748164748478317454508" something like this? It might be a  Polybius square cipher, where each 2-number block in the encrypted text is a coordinate on a 5x5 square.

* If we examine the encrypted string, we see that when divided into blocks of 2 every first letter, x, falls on the interval 0<=x<=4 and every second letter, y, falls on the interval 5<=y<=9. This knowledge combined with the hint that our cipher will be missing the letter "z", we can construct a 5x5 Polybius square (hence the hint sqrt(ABCDEFGHIJKLMNOPQRSTUVWXY), because the alphabet minus Z is of length 25 and sqrt(25) = 5).

* Provided with RSA p,q,dp,dq and ciphertext utilize [RSA](https://raw.githubusercontent.com/LFlare/picoctf_2017_writeup/master/cryptography/weird-rsa/solve.py)

* If you see multiple flags, which may mean something. Maybe have a look at [International Maritime Signal Flags](https://en.wikipedia.org/wiki/International_maritime_signal_flags)

## Encryption / Decryption / Hashing Techniques

## Encryption

> Data encryption translates data into another form, or code, so that only people with access to a secret key (formally called a decryption key) or password can read it. Encrypted data is commonly referred to as ciphertext, while unencrypted data is called plaintext

## Decryption

> The conversion of encrypted data into its original form is called Decryption. It is generally a reverse process of encryption. It decodes the encrypted information so that an authorized user can only decrypt the data because decryption requires a secret key or password.

## Hashing

> Hashing is the process of converting a given key into another value. ... The result of a hash function is known as a hash value or simply, a hash. A good hash function uses a one-way hashing algorithm, or in other words, the hash cannot be converted back into the original key

### Popular Hashing Algorithms

* MD5
* SHA-Family [SHA-224, SHA-256 or 512 bits: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256]
* Etc. Diffrent [Hashing Algorithms](https://en.wikipedia.org/wiki/List_of_hash_functions)

### How To Decrypt Hash

#### MD5

> It is 128 bits Algorithm  Like This [6226f7cbe59e99a90b5cef6f94f966fd]
> To Decrypt This Hash Use [CrackStation](https://crackstation.net/)

#### SHA Family

> In cryptography, SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function which takes an input and produces a 160-bit (20-byte) hash value known as a message digest – typically rendered as a hexadecimal number, 40 digits long
**Digest sizes: 160 bits**
**Block sizes: 512 bits**

```
Example :

Input : hello world

Output : 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
```

> You Can Check Using [Cyber Chef](https://gchq.github.io/CyberChef/)
> CyberChef : You can  Encrypt And Decrypt Diffrent Types Of Algorithms / Hashes / Ciphers Using This Tool.

### RSA

> RSA (Rivest–Shamir–Adleman) is an algorithm used by modern computers to encrypt and decrypt messages. It is an asymmetric cryptographic algorithm. Asymmetric means that there are two different keys. This is also called public key cryptography, because one of the keys can be given to anyone.

### Example

> p = 79 , q = 89 , message = 44

```py
from decimal import Decimal 
  
def gcd(m,n): 
    if n==0: 
        return a 
    else: 
        return gcd(n,m%n) 

p = input()
q = input()
no = input()
#calculate n
n = p*q 

totient = (p-1)*(q-1) 
#calculate K
for k in range(2,totient): 
    if gcd(k,totient)== 1: 
        break
  
  
for i in range(1,10): 
    x = 1 + i*totient 
    if x % k == 0: 
        d = int(x/k) 
        break
local_cipher = Decimal(0) 
local_cipher =pow(message,k) 
cipher_text = ctt % n 
  
decrypt_t = Decimal(0) 
decrypt_t= pow(cipher_text,d) 
decrpyted_text = decrypt_t % n 
  
print('n = '+str(n))
print(' k = '+str(k))
print(' totient = '+str(t))
print(' d = '+str(d)) 
print('cipher text = '+str(ct))
print(' decrypted text = '+str(dt))

```

### Base Family

* Base32, Base58, Base62, Base64, Base85

> To recognize this must see the last part of the ciphertext, Sometimes Its end with "==" double equal to. Use [CyberChef](https://gchq.github.io/CyberChef/) To Recognize the base.

```css
This is base32 : KRUGS4ZANFZSAYTBONSTGMQ=
This is base58 : Y2oxCuAXwVJeXksc9f5
This is base62 : 9LDeVysKRt9Msno4rGU
This is base64 : VGhpcyBpcyBiYXNlNjQ==
This is base85 : <+oue+DGm>@UX=h3&L
```

## Ciphers

> All are the CipherText Algorithms And Ciphertext meanse PlainText + Encryption Algorithms = CipherText

* [ROT13](https://www.dcode.fr/rot-13-cipher)
* [ROT47](https://www.dcode.fr/rot-47-cipher)
* [Atbash Cipher](https://www.dcode.fr/atbash-cipher)
* [Caesar Cipher](https://www.dcode.fr/caesar-cipher)
* [Rail-fence Cipher](https://www.dcode.fr/rail-fence-cipher)
* [Affine Cipher](https://www.dcode.fr/affine-cipher)
* [Baconian Cipher](https://www.dcode.fr/bacon-cipher)
* [Polybius Square Cipher](https://www.dcode.fr/polybius-cipher)
* [Simple Substitution Cipher](https://www.dcode.fr/caesar-cipher)
* [Codes and Nomenclators Cipher](https://www.dcode.fr/nomenclator-cipher)
* [Columnar Transposition Cipher](https://www.dcode.fr/columnar-transposition-cipher)
* [Autokey Cipher](https://www.dcode.fr/autoclave-cipher)
* [Vigenère and Gronsfeld Cipher](https://www.dcode.fr/gronsfeld-cipher)
* [Hill Cipher](https://www.dcode.fr/hill-cipher)
* [Playfair Cipher](https://www.dcode.fr/playfair-cipher)
* [Etc..](https://www.dcode.fr)

> This all methods are use to convert your plaintext in to ciphertext so that your plain text is secure from others

## EsoLangs

> An esoteric programming language (sometimes shortened to esolang) is a programming language designed to test the boundaries of computer programming language design, as a proof of concept, as software art, as a hacking interface to another language.

* [Befunge](https://www.tutorialspoint.com/compile_befunge_online.php)
* [Binary lambda calculus](https://tromp.github.io/cl/Binary_lambda_calculus.html)
* [Brainfuck](https://www.dcode.fr/brainfuck-language)
* [FRACTRAN](http://lomont.org/posts/2017/fractran/)
* [GolfScript](https://tio.run/#golfscript)
* [INTERCAL](https://tio.run/#intercal)
* [JSFuck](http://www.jsfuck.com/)
* [LOLCODE](https://tio.run/#lolcode)
* [Whitespace](https://tio.run/#whitespace)
* [Unlambda](https://tio.run/#unlambda)
* [Shakespeare](https://tio.run/#spl)
* [Piet](https://tio.run/#piet)
* [Malbolge](https://tio.run/#malbolge)

> Listed above is diffrent kind of esolang and there is lot more. [Tio](https://tio.run/)
