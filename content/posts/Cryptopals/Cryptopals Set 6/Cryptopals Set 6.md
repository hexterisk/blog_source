---
author:
  name: "hexterisk"
date: 2020-04-10
linktitle: Set 6
type:
- post
- posts
title: Set 6
tags: ["Matasano", "cryptography", "DSA", "RSA", "Bleichenbacher", "nonce", "xor", "e=3", "PKCS#1", "oracle", "PKCS1.5"]
weight: 10
categories: ["Cryptopals"]
---

### Challenge 41: Implement unpadded message recovery oracle
[Link](https://cryptopals.com/sets/6/challenges/41)

> Nate Lawson says we should stop calling it "RSA padding" and start calling it "RSA armoring". Here's why.  
> Imagine a web application, again with the Javascript encryption, taking RSA-encrypted messages which (again: Javascript) aren't padded before encryption at all.  
> You can submit an arbitrary RSA blob and the server will return plaintext. But you can't submit the same message twice: let's say the server keeps hashes of previous messages for some liveness interval, and that the message has an embedded timestamp: \*\* {  
> time: 1356304276,  
> social: '555-55-5555',  
> }  
> You'd like to capture other people's messages and use the server to decrypt them. But when you try, the server takes the hash of the ciphertext and uses it to reject the request. Any bit you flip in the ciphertext irrevocably scrambles the decryption.  
> This turns out to be trivially breakable:
> 
> *   Capture the ciphertext C
> *   Let N and E be the public modulus and exponent respectively
> *   Let S be a random number > 1 mod N. Doesn't matter what.
> *   Now:  
>     **C' = ((S\*\*E mod N) C) mod N**
> *   Submit C', which appears totally different from C, to the server, recovering P', which appears totally different from P
> *   Now:   
>     **P = P' / S mod N**
> 
> Oops!  
> Implement that attack.

```python
# Imports
import random
```

Define a class that works as a server as described by the question.

```python
class RSA_server(RSA):
    """
    Extends the RSA class to verify that no ciphertext passes through more than once.
    """
    
    decrypted = []
    
    def get_public_key(self: object) -> tuple:
        return self.pub
    
    def decrypt_check(self: object, ciphertext: bytes) -> bytes:
        if ciphertext in self.decrypted:
            raise Exception("This ciphertext has already been deciphered before!")
        self.decrypted.append(ciphertext)
        return self.decrypt(ciphertext)
```

This attack focuses on a particular property of RSA: homorphism. The output(ciphertext) of an RSA encryption engine is a number, and therefore any operation carried out on this is reflected on the plaintext produced when we decrypt this ciphertext, and thus preserves the original state of the plaintext.

Once we obtain a ciphertext, we can ask the oracle to decrypt multiples of ciphertext( ie _2 \* ciphertext_, _3 \* ciphertext_, …_n \* ciphertext_ where _n_ is an integer). We can then use the result of these decryptions to obtain the original plaintext by just dividing the scaling factor for the respective ciphertexts.

```python
def unpadded_message_recovery(ciphertext: bytes, rsa_server: object) -> bytes:
    """
    Modifies ciphertext and recovers plaintext from an RSA server.
    """
    
    (E, N) = rsa_server.get_public_key()
    S = random.randint(1, N)
    while True:
        if S % N > 1:
            break
    
    modified_ciphertext = (pow(S, E, N) * ciphertext) % N
    
    modified_plaintext = rsa_server.decrypt_check(modified_ciphertext)
    recovered_plaintext_int = (int.from_bytes(modified_plaintext, "big") * mod_inverse(S, N) % N)
    
    return (recovered_plaintext_int).to_bytes((recovered_plaintext_int.bit_length() + 7) // 8, "big")
```
```python
rsa_server = RSA_server(256)
plaintext = "Unpadded message"
ciphertext = rsa_server.encrypt(plaintext.encode())
```

{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}

### Challenge 42: Bleichenbacher's e=3 RSA Attack
[Link](https://cryptopals.com/sets/6/challenges/42)

> RSA with an encrypting exponent of 3 is popular, because it makes the RSA math faster.  
> With e=3 RSA, encryption is just cubing a number mod the public encryption modulus:  
> **c = m \*\* 3 % n**  
> e=3 is secure as long as we can make assumptions about the message blocks we're encrypting. The worry with low-exponent RSA is that the message blocks we process won't be large enough to wrap the modulus after being cubed. The block 00:02 (imagine sufficient zero-padding) can be "encrypted" in e=3 RSA; it is simply 00:08.  
> When RSA is used to sign, rather than encrypt, the operations are reversed; the verifier "decrypts" the message by cubing it. This produces a "plaintext" which the verifier checks for validity.  
> When you use RSA to sign a message, you supply it a block input that contains a message digest. The PKCS1.5 standard formats that block as:  
> **00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH**  
> As intended, the ffh bytes in that block expand to fill the whole block, producing a "right-justified" hash (the last byte of the hash is the last byte of the message).  
> There was, 7 years ago, a common implementation flaw with RSA verifiers: they'd verify signatures by "decrypting" them (cubing them modulo the public exponent) and then "parsing" them by looking for 00h 01h ... ffh 00h ASN.1 HASH.  
> This is a bug because it implies the verifier isn't checking all the padding. If you don't check the padding, you leave open the possibility that instead of hundreds of ffh bytes, you have only a few, which if you think about it means there could be squizzilions of possible numbers that could produce a valid-looking signature.  
> How to find such a block? Find a number that when cubed (a) doesn't wrap the modulus (thus bypassing the key entirely) and (b) produces a block that starts "00h 01h ffh ... 00h ASN.1 HASH".  
> There are two ways to approach this problem:
> 
> *   You can work from Hal Finney's writeup, available on Google, of how Bleichenbacher explained the math "so that you can do it by hand with a pencil".
> *   You can implement an integer cube root in your language, format the message block you want to forge, leaving sufficient trailing zeros at the end to fill with garbage, then take the cube-root of that block.
> 
> Forge a 1024-bit RSA signature for the string "hi mom". Make sure your implementation actually accepts the signature!

```python
# Imports
import re
import hashlib

# Given
message = "hi mom"

ASN1_SHA1 = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
```

NOTE: The attack works specifically for e = 3, as mentioned in the question itself.

PKCS#1 v1.5 says that the hash of the message to be signed has to be encoded in the form like: `00 01 FF FF ... FF FF 00 ASN.1 HASH` 

The signature generation goes like: _mᵈ mod N_

While, the signature verification goes like: _(mᵈ)ᵉ = m mod N_

Numbers have to be in big endian because cubing takes place, and interferes with the bit manipulation.

```python
class RSA_Digital_Signature(RSA):
    """
    Extends the RSA class coded before with the sign / verify functions.
    """

    def generate_signature(self: object, message: bytes) -> bytes:
        digest = hashlib.sha1(message).digest()
        block = b'\x00\x01' + (b'\xff' * (128 - len(digest) - 3 - 15)) + b'\x00' + ASN1_SHA1 + digest
        signature = self.decrypt(int.from_bytes(block, "big"), "big")
        return signature

    def verify_signature(self: object, message: bytes, signature: bytes) -> bool:
        cipher = self.encrypt(signature, "big")
        block = b'\x00' + cipher.to_bytes((cipher.bit_length() + 7) // 8, "big")
        r = re.compile(b'\x00\x01\xff+?\x00.{15}(.{20})', re.DOTALL)
        m = r.match(block)
        if not m:
            return False
        digest = m.group(1)
        return digest == hashlib.sha1(message).digest()
```
Test the oracle.

```python
rsa = RSA_Digital_Signature(1024)
signature = rsa.generate_signature(message.encode())
if not rsa.verify_signature(message.encode(), signature):
    raise Exception(message + b" has invalid signature " + signature)
else:
    print("> Signature verified for message:", message)
```
`> Signature verified for message: hi mom`

A broken padding validator(and this is pretty common) might just check for the presence of `FF 00 ASN.1` and would simply parse the `HASH` present right after. This leaves us the room to play with the bytes between `00 01 FF` and `FF 00 ASN.1`

Now, the caveat here is that the message is not signed. Instead, the PKCS#1 padded hash of the message is signed.

Therefore, if _e = 3_, we can pass a value that when cubed and and having the modulus operation applied, passes the format check.

It will then be in the form `00 01 FF FF ... FF FF 00 ASN.1 HASH ADDED_HASH` 

Thus, forging message simply means to find such a number as described above, which will pass the verification and carry our message.

```python
def forge_signature(message: bytes) -> bytes:
    """
    Forges the SHA1 signature of the message
    """
    digest = hashlib.sha1(message).digest()
    block = b'\x00\x01\xff\x00' +  ASN1_SHA1 + digest + (b'\x00' * (128 - len(digest) - 4 - 15))
    block_int = int.from_bytes(block, "big")
    sig = floorRoot(block_int, 3) + 1
    return sig.to_bytes((sig.bit_length() + 7) // 8, "big")
```
```python
forged_signature = forge_signature(message.encode())
if not rsa.verify_signature(message.encode(), forged_signature):
    raise Exception(message + b" has invalid signature " + forged_signature)
    test(False)
else:
    print("> Signature verified for message:", message)
```
`> Signature verified for message: hi mom`

{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}

### Challenge 43: DSA key recovery from nonce
[Link](https://cryptopals.com/sets/6/challenges/43)

> DSA key recovery from nonce  
> **Step 1**: Relocate so that you are out of easy travel distance of us. **Step 2**: Implement DSA, up to signing and verifying, including parameter generation.  
> Hah-hah you're too far away to come punch us.  
> Just kidding you can skip the parameter generation part if you want; if you do, use these params:  
> **p = 800000000000000089e1855218a0e7dac38136ffafa72eda7**  
> **859f2171e25e65eac698c1702578b07dc2a1076da241c76c6**  
> **2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe**  
> **ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2**  
> **b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87**  
> **1a584471bb1**  
> **q = f4f47f05794b256174bba6e9b396a7707e563c5b**  
> **g = 5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119**  
> **458fef538b8fa4046c8db53039db620c094c9fa077ef389b5**  
> **322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047**  
> **0f5b64c36b625a097f1651fe775323556fe00b3608c887892**  
> **878480e99041be601a62166ca6894bdd41a7054ec89f756ba**  
> **9fc95302291**  
> ("But I want smaller params!" Then generate them yourself.)  
> The DSA signing operation generates a random subkey "k". You know this because you implemented the DSA sign operation.  
> This is the first and easier of two challenges regarding the DSA "k" subkey.  
> Given a known "k", it's trivial to recover the DSA private key "x":  
> **x = ((s \* k) - H(msg)) / r mod q**  
> Do this a couple times to prove to yourself that you grok it. Capture it in a function of some sort.  
> Now then. I used the parameters above. I generated a keypair. My pubkey is:  
> **y = 84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4**  
> **abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004**  
> **e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed**  
> **1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b**  
> **bb283e6633451e535c45513b2d33c99ea17**  
> I signed  
> For those that envy a MC it can be hazardous to your health  
> So be friendly, a matter of life and death, just like a etch-a-sketch  
> (My SHA1 for this string was d2d0714f014a9784047eaeccf956520045c45265; I don't know what NIST wants you to do, but when I convert that hash to an integer I get: 0xd2d0714f014a9784047eaeccf956520045c45265).  
> I get:  
> **r = 548099063082341131477253921760299949438196259240**  
> **s = 857042759984254168557880549501802188789837994940**  
> I signed this string with a broken implemention of DSA that generated "k" values between 0 and 2^16. What's my private key?  
> Its SHA-1 fingerprint (after being converted to hex) is:  
> **0954edd5e0afe5542a4adf012611a91912a3ec16**  
> Obviously, it also generates the same signature for that string.

```python
# Imports
import random
import hashlib
from Crypto.Util.number import getPrime
```

Define a class that implements the [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) algorithm.

```python
class DSA:
    """
    Implements the DSA public key encryption / decryption.
    Steps followed are from Wikipedia.
    """
    
    DEFAULT_P = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76"
                    "c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232"
                    "c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
    DEFAULT_Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    DEFAULT_G = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389"
                    "b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c88"
                    "7892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)
        
    def __init__(self: object, p = DEFAULT_P, q = DEFAULT_Q, g = DEFAULT_G):
        self.p = p
        self.q = q
        self.g = g
        self.x, self. y = self._per_user_key()
        self.pvt, self.pub = self.x, self.y
        
    def _per_user_key(self: object):
        x = random.randint(1, self.q - 1)
        y = pow(self.g, x, self.p)
        return x, y
    
    def H(self: object, message: bytes) -> bytes:
        return int(hashlib.sha1(message).hexdigest(), 16)
    
    def key_distribution(self: object) -> tuple:
        return self.pub
    
    def generate_signature(self: object, message: bytes) -> (int, int):
        
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue
                
            s = (mod_inverse(k, self.q) * (self.H(message) + self.x * r)) % self.q
            if s != 0:
                break
        return (r, s)
    
    def verify_signature(self: object, r: int, s: int, message: bytes) -> bool:
        if r < 0 or r > self.q:
            return False
        if s < 0 or s > self.q:
            return False
        
        w = mod_inverse(s, self.q)
        u1 = (self.H(message) * w) % self.q
        u2 = (r * w) % self.q
        
        v1 = pow(self.g, u1, self.p)
        v2 = pow(self.y, u2, self.p)
        
        v = ((v1 * v2) % self.p) % self.q
        return v == r
```

Function to generate DSA parameters as described in the algorithm.

```python
def DSA_parameter_generation(key_length: int) -> (int, int, int):
    """
    Generates DSA parameters as described by the pseudo code on wikipedia.
    """
    # Filter object is created, iter is used to fetch values and then tuple is accessed
    modulo_list = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]    

    N = filter(lambda x:key_length in x, modulo_list).__next__()[1]
    q = getPrime(N)
    
    p = 0
    while True:
        p = getPrime(key_length)
        if (p - 1) % q == 0:
            break

    g = 1
    h = 0
    
    while True:
        h = random.randint(2, p - 2)
        g = h**((p - 1) / q)
        if g != 1:
            break
    
    return p, q, gDSA_x_from_k

# Takes a lot of time
# p, q, g = DSA_parameter_generation(1024)
# dsa = DSA(p, q, g)
```

Test if the DSA implementation works.

```python
dsa = DSA()
signature = dsa.generate_signature(b"Hello World!")
assert dsa.verify_signature(signature[0], signature[1], b"Hello World!")
```
Looking at the equation used during signature(r, s) generation:

_s = (mod\_inverse(k, self.q) \* (self.H(message) + self.x \* r)) % self.q_

It can be rearranged for all the known variables to be on the right, and the unknown (private key x) to be on the left.

```python
def DSA_x_from_k(k: int, q: int, r: int, s: int, message_int: int) -> int:
    """
    Returns the value of x as calculated using other parameters.
    """
    return (((s * k) - message_int) * mod_inverse(r, q)) % q
```

Brute forcing all possible values of _k_ uptil 256, since the question says:

> implemention of DSA that generated "k" values between 0 and 2^16.

```python
def key_recovery_from_nonce(q: int, r: int, s: int, y: int, message_int: int):
    """
    Verify if the key recovered from nonce is the same as given in question.
    """
    
    # Given
    target = "0954edd5e0afe5542a4adf012611a91912a3ec16"
    
    # This loop goes over all possibilities.
    for k in range(2**16):
        x = DSA_x_from_k(k, q, r, s, message_int)
        
        # [2:] tp skip the 0x
        if hashlib.sha1(hex(x)[2:].encode()).hexdigest() == target:
            return x
    return 0
```
```python
# Given
message = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
# Used to verify if our implementation works correctly
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940
y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a0808"
        "4056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec56828"
        "0ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940
y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a0808"
        "4056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec56828"
        "0ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)

key = key_recovery_from_nonce(q, r, s, y, dsa.H(message.encode()))
if key != 0:
    print("> Brute force successful.\nPrivate key:", key)
    test(True)
else:
    test(False)
```
`> Brute force successful.`

`Private key: 125489817134406768603130881762531825565433175625`

{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}

### Challenge 44: DSA nonce recovery from repeated nonce
[Link](https://cryptopals.com/sets/6/challenges/44)

> [In this file find a collection of DSA-signed messages.](https://cryptopals.com/static/challenge-data/44.txt) (NB: each msg has a trailing space.)  
> These were signed under the following pubkey:  
> **y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07 13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8 5519b1c23cc3ecdc6062650462e3063bd179c2a6581519 f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430 f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3 2971c3de5084cce04a2e147821**  
> (using the same domain parameters as the previous exercise)  
> It should not be hard to find the messages for which we have accidentally used a repeated "k". Given a pair of such messages, you can discover the "k" we used with the following formula:  
> **k = (m1 - m2) / (s1 - s2) mod q**  
> What's my private key? Its SHA-1 (from hex) is:  
> **ca8f6f7c66fa362d40760d135b763eb8527d3d52**

```python
# Imports
import hashlib
```
```python
# Given
data = open("44.txt", "r").read()
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
y = int("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
    "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a"
    "6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)

target = "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
```

Find two pairs of signatures that used the same k.  
This is easy to find, because when the same k is used r will be the same, since r depends only on (g, p, q and k), and (g, p, q) are fixed in our implementation.

Calculate the value k with the given equation and then follow the previous question.

```python
def nonce_recovery_from_repeated_nonce(message_dicts: dict, q: int) -> int:
    """
    Finds the signature pair using the same value for k from the given strings.
    """

    # Find indices of signatures with matching r.
    found = False
    r1, s1, s2, m1, m2 = 0, 0, 0, 0, 0
    for i in range(len(message_dicts)):
        for j in range(len(message_dicts[i:])):
            if message_dicts[i]["r"] == message_dicts[j]["r"]:
                m1 = message_dicts[i]["m"]
                m2 = message_dicts[j]["m"]
                if m1 == m2:
                    continue
                found = True
                r1 = message_dicts[i]["r"]
                s1 = message_dicts[i]["s"]
                s2 = message_dicts[j]["s"]                
                break
        if found:
            break
    # Calculate the value of k once matching r has been found.
    k = (((m1 - m2) % q) * mod_inverse((s1 - s2) % q, q)) % q
    return DSA_x_from_k(k, q, r1, s1, m1)
```
```python
data_list = data.split('\n')
message_dicts = []
for i in range(0, len(data_list)-4, 4):
    message_dicts.append({"msg":data_list[i][5:], "s":int(data_list[i + 1][3:]), "r":int(data_list[i + 2][3:]), "m":int(data_list[i + 3][3:], 16)})

recovered_x = nonce_recovery_from_repeated_nonce(message_dicts, q)
hashlib.sha1(hex(recovered_x)[2:].encode()).hexdigest()
```

{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}

### Challenge 45: DSA parameter tampering
[Link](https://cryptopals.com/sets/6/challenges/45)

> Take your DSA code from the previous exercise. Imagine it as part of an algorithm in which the client was allowed to propose domain parameters (the p and q moduli, and the g generator).  
> This would be bad, because attackers could trick victims into accepting bad parameters. Vaudenay gave two examples of bad generator parameters: generators that were 0 mod p, and generators that were 1 mod p.  
> Use the parameters from the previous exercise, but substitute 0 for "g". Generate a signature. You will notice something bad. Verify the signature. Now verify any other signature, for any other string.  
> Now, try (p+1) as "g". With this "g", you can generate a magic signature s, r for any DSA public key that will validate against any string. For arbitrary z:  
> **r = ((y\*\*z) % p) % q**  
> **s = r / z --- % q**  
> Sign "Hello, world". And "Goodbye, world".

The DSA implementation from previous question, but with an introduced vulnerability.

```python
class DSA_flawed(DSA):
    """
    Extends the DSA public key encryption / decryption.
    Allows r = 0, hence flawed.
    """
    
    def generate_signature(self: object, message: bytes) -> (int, int):
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q                
            s = (mod_inverse(k, self.q) * (self.H(message) + self.x * r)) % self.q
            if s != 0:
                break
        return (r, s)
```

Test if the DSA flawed implementation works.

The idea here is that _g = 0_

    ⇨ r = 0 since `r = pow(self.g, k, self.p) % self.q`

    ⇨ s = 0 since `s = (mod_inverse(k, self.q) * (self.H(message) + self.x * r)) % self.q`

Therefore, the signature will always be valid for any message (refer the `verify_signature` method of the DSA class and follow the math to verify).

```python
dsa = DSA_flawed(g = 0)
message = "Original message"

signature = dsa.generate_signature(message.encode())
print("> Message:", message)
print("> Signature generated for g = 0.\nr:", signature[0], "\ns:", signature[1])
check = dsa.verify_signature(signature[0], signature[1], message.encode())
if check:
    print("> Signature successfully verified.")
    
tampered_message = "Tampered message!"
print("> Trying to verify signature of initial message for message:", tampered_message)
print("> Values from previous signature:\nr:", signature[0], "\ns:", signature[1])
check = dsa.verify_signature(signature[0], signature[1], tampered_message.encode())
if check:
    print("> Signature successfully verified.")
```
`> Message: Original message`
`> Signature generated for g = 0.`

`r: 0 `
`s: 1319384916910796403481505255729961366741861352600`
`> Signature successfully verified.`

`> Trying to verify signature of initial message for message: Tampered message!`
`> Values from previous signature:`
`r: 0 `
`s: 1319384916910796403481505255729961366741861352600`
`> Signature successfully verified.`

Now, for _g = (p + 1)_, applying modulus with _p_ to it will give _1_, which raised to any power will always return _1_.

Thus we can yet again forge signature for any string. 

```python
def DSA_parameter_tampering() -> bool:
    """
    Parameter tampering for a flawed DSA.
    Exploits the vulnerability where value of r is not checked for zero.
    """

    dsa = DSA_flawed(g = DSA.DEFAULT_P + 1)
    message = "g = (p + 1) DSA"
    signature = dsa.generate_signature(message.encode())
    print("> Message:", message)
    print("> Signature generated for g = (p + 1).\nr:", signature[0], "\ns:", signature[1])
    check = dsa.verify_signature(signature[0], signature[1], message.encode())
    if check:
        print("> Signature successfully verified for original message.")
    
    z = random.randint(1, 100)
    y = dsa.key_distribution()
    forged_r = pow(y, z, DSA_flawed.DEFAULT_P) % DSA_flawed.DEFAULT_Q
    forged_s = (forged_r * mod_inverse(z, dsa.DEFAULT_Q)) % dsa.DEFAULT_Q
    
    message1 = "Hello, world"
    message2 = "Goodbye, world"
    
    print("> Values from forged signature:\nr:", forged_r, "\ns:", forged_s)
    
    print("> Message 1:", message1)
    if dsa.verify_signature(forged_r, forged_s, message1.encode()):
        print("> Signature successfully verified for message 1.")
    print("> Message 2:", message2)
    if dsa.verify_signature(forged_r, forged_s, message2.encode()):
        print("> Signature successfully verified for message 2.")
        return True
```
`> Message: g = (p + 1) DSA`

`> Signature generated for g = (p + 1).`

`r: 1 `

`s: 703825769835692073972406982417451225320756768361`

`> Signature successfully verified for original message.`

`> Values from forged signature:`

`r: 1 `

`s: 719200900302382415334968953803618372055900244717`

`> Message 1: Hello, world`

`> Signature successfully verified for message 1.`

`> Message 2: Goodbye, world`

`> Signature successfully verified for message 2.`

{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}

### Challenge 46: RSA parity oracle
[Link](https://cryptopals.com/sets/6/challenges/46)

> Generate a 1024 bit RSA key pair.  
> Write an oracle function that uses the private key to answer the question "is the plaintext of this message even or odd" (is the last bit of the message 0 or 1). Imagine for instance a server that accepted RSA-encrypted messages and checked the parity of their decryption to validate them, and spat out an error if they were of the wrong parity.  
> Anyways: function returning true or false based on whether the decrypted plaintext was even or odd, and nothing else.  
> Take the following string and un-Base64 it in your code (without looking at it!) and encrypt it to the public key, creating a ciphertext: **VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb**  
**2xkIE1lZGluYQ==**  
> With your oracle function, you can trivially decrypt the message. Here's why:
> 
> *   RSA ciphertexts are just numbers. You can do trivial math on them. You can for instance multiply a ciphertext by the RSA-encryption of another number; the corresponding plaintext will be the product of those two numbers.
> *   If you double a ciphertext (multiply it by (2\*\*e)%n), the resulting plaintext will (obviously) be either even or odd.
> *   If the plaintext after doubling is even, doubling the plaintext didn't wrap the modulus --- the modulus is a prime number. That means the plaintext is less than half the modulus.
> 
> You can repeatedly apply this heuristic, once per bit of the message, checking your oracle function each time.  
> Your decryption function starts with bounds for the plaintext of \[0,n\].  
> Each iteration of the decryption cuts the bounds in half; either the upper bound is reduced by half, or the lower bound is.  
> After log2(n) iterations, you have the decryption of the message.  
> Print the upper bound of the message as a string at each iteration; you'll see the message decrypt "hollywood style".  
> Decrypt the string (after encrypting it to a hidden private key) above.

```python
# Imports
import math
import base64
import decimal
```
```python
# Given
given_string = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
```

Answers the question mentioned in the challenge:  
"is the plaintext of this message even or odd" (is the last bit of the message 0 or 1)

```python
def check_parity(ciphertext: int, rsa: object) -> int:
    """
    Returns the last bit of the number.
    """
    return rsa.decryptnum(ciphertext) &amp; 1
```
Test the parity check function.

```python
rsa = RSA(1024)
ciphertext = rsa.encrypt(b"Hello")
print(check_parity(ciphertext, rsa))
```
`1`

The idea is to multiply the number by factors of 2 to check if the number wrapped around the modulus.

Refer to this post on [crypto.stackexchange](https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack) for an explanation.

```python
def parity_attack(message: bytes, rsa: object) -> int:
    """
    Parity attack on RSA
    """
    
    (_, n) = rsa.pub
    ciphertext = rsa.encryptnum(int.from_bytes(message, "big"))
    
    # encrypt multiplier
    multiplier = rsa.encryptnum(2)
    
    # Initialize lower and upper bound.
    # I need to use Decimal because it allows me to set the precision for the floating point
    # numbers, which we will need when doing the binary search divisions.
    lower_bound = decimal.Decimal(0)
    upper_bound = decimal.Decimal(n)
    
    # Compute the number of iterations that we have to do
    num_iter = int(math.ceil(math.log(n, 2)))
    # Set the precision of the floating point number to be enough
    decimal.getcontext().prec = num_iter

    for _ in range(num_iter):
        ciphertext = (ciphertext * multiplier) % n
        
        # checking parity
        if check_parity(ciphertext, rsa) &amp; 1:
            lower_bound = (lower_bound + upper_bound) / 2
        else:
            upper_bound = (lower_bound + upper_bound) / 2

    # Return the binary version of the upper_bound (converted from Decimal to int)
    return int(upper_bound).to_bytes((int(upper_bound).bit_length() + 7) // 8, "big").decode("utf-8")
```
```python
byte_string = base64.b64decode(given_string)
plaintext = parity_attack(byte_string, RSA(1024))
```

{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}

### Challenge 47: Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
[Link](https://cryptopals.com/sets/6/challenges/47)

> Let us Google this for you: ["Chosen ciphertext attacks against protocols based on the RSA encryption standard"](https://lmgtfy.com/?q=%22Chosen+ciphertext+attacks+against+protocols+based+on+the+RSA+encryption+standard%22)  
> This is Bleichenbacher from CRYPTO '98; I get a bunch of .ps versions on the first search page.  
> Read the paper. It describes a padding oracle attack on PKCS#1v1.5. The attack is similar in spirit to the CBC padding oracle you built earlier; it's an "adaptive chosen ciphertext attack", which means you start with a valid ciphertext and repeatedly corrupt it, bouncing the adulterated ciphertexts off the target to learn things about the original.  
> This is a common flaw even in modern cryptosystems that use RSA.  
> It's also the most fun you can have building a crypto attack. It involves 9th grade math, but also has you implementing an algorithm that is complex on par with finding a minimum cost spanning tree.  
> The setup:
> 
> *   Build an oracle function, just like you did in the last exercise, but have it check for plaintext\[0\] == 0 and plaintext\[1\] == 2.
> *   Generate a 256 bit keypair (that is, p and q will each be 128 bit primes), \[n, e, d\].
> *   Plug d and n into your oracle function.
> *   PKCS1.5-pad a short message, like "kick it, CC", and call it "m". Encrypt to to get "c".
> *   Decrypt "c" using your padding oracle.
> 
> For this challenge, we've used an untenably small RSA modulus (you could factor this keypair instantly). That's because this exercise targets a specific step in the Bleichenbacher paper --- Step 2c, which implements a fast, nearly O(log n) search for the plaintext.  
> Things you want to keep in mind as you read the paper:
> 
> *   RSA ciphertexts are just numbers.
> *   RSA is "homomorphic" with respect to multiplication, which means you can multiply c \* RSA(2) to get a c' that will decrypt to plaintext \* 2. This is mindbending but easy to see if you play with it in code --- try multiplying ciphertexts with the RSA encryptions of numbers so you know you grok it.
> *   What you need to grok for this challenge is that Bleichenbacher uses multiplication on ciphertexts the way the CBC oracle uses XORs of random blocks.
> *   A PKCS#1v1.5 conformant plaintext, one that starts with 00:02, must be a number between 02:00:00...00 and 02:FF:FF..FF --- in other words, 2B and 3B-1, where B is the bit size of the modulus minus the first 16 bits. When you see 2B and 3B, that's the idea the paper is playing with.
> 
> To decrypt "c", you'll need Step 2a from the paper (the search for the first "s" that, when encrypted and multiplied with the ciphertext, produces a conformant plaintext), Step 2c, the fast O(log n) search, and Step 3.  
> Your Step 3 code is probably not going to need to handle multiple ranges.  
> We recommend you just use the raw math from paper (check, check, double check your translation to code) and not spend too much time trying to grok how the math works.

```python
# Imports
import os
import random
```
```python
# Given
message = "kick it, CC"
```

RSA Oracle extended to check for PKCS1 padding.

```python
class RSA_PKCS1_Oracle(RSA):
    """
    Extends the RSA class by making the decryption PKCS 1.5 compliant and by adding a method
    to verify the padding of data.
    """
    
    def PKCS1_Pad(self: object, message: bytes) -> bytes:
        """
        Pads the given binary data conforming to the PKCS 1.5 format.
        """
        
        (e, n) = self.pub
        byte_length = (n.bit_length() + 7) // 8
        padding_string = os.getrandom(byte_length - 3 - len(message))
        return b"\x00\x02" + padding_string + b'\x00' + message
    
    def PKCS1_check_padding(self: object, ciphertext: int) -> bool:
        """
        Decrypts the input data and returns whether its padding is correct according to PKCS 1.5.
        """
        
        _, n = self.pub
        k = (n.bit_length() + 7) // 8
        pbytes = self.decrypt(ciphertext)
        pbytes = (b'\x00' * (k - len(pbytes))) + pbytes
        return pbytes[0:2] == b'\x00\x02'
```

Function to aid in calculation.

```python
def ceil(a: int, b: int) -> int:
    """
    Returns the ceil of division between two numbers.
    """
    return (a + b - 1) // b
```
Function aid in Padding Oracle Attack.

```python
def append_interval(M_narrow: list, lower_bound: int, upper_bound: int):
    """
    Append the passed bounds as an interval to the list.
    Write over the interval if tighter constraints are passed.
    Skip if it already exists.
    """
    
    # Check if there exist an interval which is overlapping with the lower_bound and
    # upper_bound of the new interval we want to append
    for i, (a, b) in enumerate(M_narrow):

        # If there is an overlap, then replace the boundaries of the overlapping
        # interval with the wider (or equal) boundaries of the new merged interval
        if not (b < lower_bound or a > upper_bound):
            new_a = min(lower_bound, a)
            new_b = max(upper_bound, b)
            M_narrow[i] = new_a, new_b
            return

    # If there was no interval overlapping with the one we want to add, add
    # the new interval as a standalone interval to the list
    M_narrow.append((lower_bound, upper_bound))
    return
```

Quoting the [original paper](http://archiv.infsec.ethz.ch/education/fs08/secsem/Bleichenbacher98.pdf),

> The attacker tries to find small values s\_is i ​ for which the ciphertext c⁰(sᶦ)ᵉ mod n is PKCS conforming. For each successful value for sᶦ , the attacker computes, using previous knowledge about m⁰​, a set of intervals that must contain m⁰… The third phase starts when only one interval remains. Then, the attacker has sufficient information about m⁰​ to choose sᶦ ​such that c⁰(sᶦ)ᵉ mod n is much more likely to be PKCS conforming than is a randomly chosen message. The size of sᶦ is increased gradually, narrowing the possible range of m⁰​ until only one possible value remains.

The implementation is from the steps defined in the paper.

```python
def padding_oracle_attack(ciphertext: bytes, rsa: object):
    """
    Performs the padding oracle attack on RSA ciphertext.
    """
    
    
    # Setting initial values
    
    (e, n) = rsa.pub
    k = (n.bit_length() + 7) // 8 # byte length
    B = 2**(8 * (k - 2))
    M = [(2 * B, 3 * B - 1)]
    i = 1
    
    if not rsa.PKCS1_check_padding(ciphertext):
        #Step 1 Blinding
        while True:
            s = random.randint(0, n - 1)
            c0 = (ciphertext * pow(s, e, n)) % n
            if rsa.PKCS1_check_padding(c0):
                break

    else:
        c0 = ciphertext
        
    # Step 2 Searching for PKCS conforming messages
    while True:
        # 2a
        if i == 1:
            s = (n + 3 * B - 1) // (3 * B)
            while True:
                c = (c0 * pow(s, e, n)) % n
                if rsa.PKCS1_check_padding(c):
                    break
                s += 1
        
        #2c
        # Step 2.c: Searching with one interval left
        elif len(M) == 1:
            a, b = M[0]

            # Check if the interval contains the solution
            if a == b:

                # And if it does, return it as bytes
                return b'\x00' + (a).to_bytes((a.bit_length() +7) // 8, "big")

            r = ceil(2 * (b * s - 2 * B), n)
            s = ceil(2 * B + r * n, b)

            while True:
                c = (c0 * pow(s, e, n)) % n
                if rsa.PKCS1_check_padding(c):
                    break

                s += 1
                if s > (3 * B + r * n) // a:
                    r += 1
                    s = ceil((2 * B + r * n), b)

        # Step 3: Narrowing the set of solutions
        M_new = []

        for a, b in M:
            min_r = ceil(a * s - 3 * B + 1, n)
            max_r = (b * s - 2 * B) // n

            for r in range(min_r, max_r + 1):
                l = max(a, ceil(2 * B + r * n, s))
                u = min(b, (3 * B - 1 + r * n) // s)

                if l > u:
                    raise Exception('Unexpected error: l > u in step 3')

                append_interval(M_new, l, u)

        if len(M_new) == 0:
            raise Exception('Unexpected error: there are 0 intervals.')

        M = M_new
        i += 1
```

```python
rsa = RSA_PKCS1_Oracle(256)
m = rsa.PKCS1_Pad(message.encode())

c = rsa.encrypt(m)
assert rsa.PKCS1_check_padding(c)
print("> Ciphertext padding verified.")
recovered_plaintext = padding_oracle_attack(c, rsa)
```
`> Ciphertext padding verified.`

{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}

### Challenge 48: Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)
[Link](https://cryptopals.com/sets/6/challenges/48)

> This is a continuation of challenge #47; it implements the complete BB'98 attack.  
> Set yourself up the way you did in #47, but this time generate a 768 bit modulus.  
> To make the attack work with a realistic RSA keypair, you need to reproduce step 2b from the paper, and your implementation of Step 3 needs to handle multiple ranges.  
> The full Bleichenbacher attack works basically like this:
> 
> *   Starting from the smallest 's' that could possibly produce a plaintext bigger than 2B, iteratively search for an 's' that produces a conformant plaintext.
> *   For our known 's1' and 'n', solve m1=m0s1-rn (again: just a definition of modular multiplication) for 'r', the number of times we've wrapped the modulus.
> *   'm0' and 'm1' are unknowns, but we know both are conformant PKCS#1v1.5 plaintexts, and so are between \[2B,3B\].
> *   We substitute the known bounds for both, leaving only 'r' free, and solve for a range of possible 'r' values. This range should be small!
> *   Solve m1=m0s1-rn again but this time for 'm0', plugging in each value of 'r' we generated in the last step. This gives us new intervals to work with. Rule out any interval that is outside 2B,3B.
> *   Repeat the process for successively higher values of 's'. Eventually, this process will get us down to just one interval, whereupon we're back to exercise #47.
> 
> What happens when we get down to one interval is, we stop blindly incrementing 's'; instead, we start rapidly growing 'r' and backing it out to 's' values by solving m1=m0s1-rn for 's' instead of 'r' or 'm0'. So much algebra! Make your teenage son do it for you! _Note: does not work well in practice_

```python
# Imports
import os
import random
```
```python
# Given
message = "kick it, CC"
```

The implementation is modified a bit to include one more step, as directed by the question.

```python
def padding_oracle_attack(ciphertext: bytes, rsa: object):
    """
    Performs the padding oracle attack on RSA ciphertext.
    """
    
    # Setting initial values
    
    (e, n) = rsa.pub
    k = (n.bit_length() + 7) // 8 # byte length
    B = 2**(8 * (k - 2))
    M = [(2 * B, 3 * B - 1)]
    i = 1
    
    if not rsa.PKCS1_check_padding(ciphertext):
        #Step 1 Blinding
        while True:
            s = random.randint(0, n - 1)
            c0 = (ciphertext * pow(s, e, n)) % n
            if rsa.PKCS1_check_padding(c0):
                break

    else:
        c0 = ciphertext
        
    # Step 2 Searching for PKCS conforming messages
    while True:
        # 2a
        if i == 1:
            s = (n + 3 * B - 1) // (3 * B)
            while True:
                c = (c0 * pow(s, e, n)) % n
                if rsa.PKCS1_check_padding(c):
                    break
                s += 1

        #2b
        elif len(M) >= 2:
            while True:
                s += 1
                c = (c0 * pow(s, e, n)) % n
                if rsa.PKCS1_check_padding(c):
                    break
        
        #2c
        # Step 2.c: Searching with one interval left
        elif len(M) == 1:
            a, b = M[0]

            # Check if the interval contains the solution
            if a == b:

                # And if it does, return it as bytes
                return b'\x00' + (a).to_bytes((a.bit_length() +7) // 8, "big")

            r = ceil(2 * (b * s - 2 * B), n)
            s = ceil(2 * B + r * n, b)

            while True:
                c = (c0 * pow(s, e, n)) % n
                if rsa.PKCS1_check_padding(c):
                    break

                s += 1
                if s > (3 * B + r * n) // a:
                    r += 1
                    s = ceil((2 * B + r * n), b)

        # Step 3: Narrowing the set of solutions
        M_new = []

        for a, b in M:
            min_r = ceil(a * s - 3 * B + 1, n)
            max_r = (b * s - 2 * B) // n

            for r in range(min_r, max_r + 1):
                l = max(a, ceil(2 * B + r * n, s))
                u = min(b, (3 * B - 1 + r * n) // s)

                if l > u:
                    raise Exception('Unexpected error: l > u in step 3')

                append_interval(M_new, l, u)

        if len(M_new) == 0:
            raise Exception('Unexpected error: there are 0 intervals.')

        M = M_new
        i += 1
```
```python
rsa = RSA_PKCS1_Oracle(768)
m = rsa.PKCS1_Pad(message.encode())

c = rsa.encrypt(m)
assert rsa.PKCS1_check_padding(c)
print("> Ciphertext padding verified.")
recovered_plaintext = padding_oracle_attack(c, rsa)
```
`> Ciphertext padding verified.`

{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}
