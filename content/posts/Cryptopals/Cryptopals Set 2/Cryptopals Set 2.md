---
author:
  name: "hexterisk"
date: 2020-03-21
linktitle: Set 2
type:
- post
- posts
title: Set 2
tags: ["Matasano", "cryptography", "AES", "ECB", "CBC", "bit-flipping", "xor", "base64", "PKCS#7", "pad", "unpad"]
weight: 10
categories: ["Cryptopals"]
---

Refer to this [repository](https://github.com/hexterisk/cryptopals-solutions) for solution scripts and the IPython Notebook pertaining to the explanations here.

### Challenge 9: Implement PKCS#7 padding
[Link](https://cryptopals.com/sets/2/challenges/9)

> A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.  
> One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.  
> So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,  
> **"YELLOW SUBMARINE"**  
> ... padded to 20 bytes would be:  
> **"YELLOW SUBMARINE\\x04\\x04\\x04\\x04"**

**Block Ciphers** work on blocks of plaintext(during encryption) and ciphertext(during decryption).  
Since most messages are irregularly sized and need to be padded up to the block size.

The [PKCS#7 RFC](https://tools.ietf.org/html/rfc2315)(10.3 note 2) states:

> For such algorithms, the method shall be to pad the input at the trailing end with k - (l mod k) octets all having value k - (l mod k), where l is the length of the input.

!["pkcs#7"](Set%202/image.png)
_Valid PKCS#7 padding._

Therefore, a message whose length is short of the block size by x, is to be padded by the x byte itself. It allows block sizes up to 255 bytes.

Since the plaintext length is short of the block size by 4 bytes, it is padded by 4 '\\x04' bytes.

```python
# Given
plaintext = "YELLOW SUBMARINE"
target_bytes = b"YELLOW SUBMARINE\x04\x04\x04\x04"
block_size = 20
```
```python
def PKCS7_pad(plaintext: bytes, block_size: int) -> bytes:
    """
    Pad the given text upto the length of given block_size following PKCS7 norms.
    """
    if len(plaintext) == block_size:
        return plaintext
    pad = block_size - len(plaintext) % block_size
    plaintext += (pad.to_bytes(1,"big"))*pad
    return plaintext
```

```python
test(PKCS7_pad(plaintext.encode(), block_size) == target_bytes)
```
{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}



### Challenge 10: Implement CBC mode
[Link](https://cryptopals.com/sets/2/challenges/10)

> CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.  
> In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.  
> The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.  
> Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.  
> [The file here](https://cryptopals.com/static/challenge-data/10.txt) is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\\x00\\x00\\x00 &c)  
> Don't cheat.

```python
# Imports
import base64
from Crypto.Cipher import AES
```
```python
# Given
inf = open("10.txt", "r")
b64_data = inf.readlines()

key = b"YELLOW SUBMARINE"
```

Since it's a block cipher, chances are that the original plaintext message was padded. Therefore, we write an unpad function(and consequently a helper function to check if padding exists), to format the resulting deciphered text accordingly.

```python
def PKCS7_padded(text: bytes) -> bool:
    """
    Checks if the given text is padded according to the PKCS7 norms.
    """
    padding = text[-text[-1]:]
    
    # Check that all the bytes in the range indicated by the padding are equal to the padding value itself.
    return all(padding[b] == len(padding) for b in range(0, len(padding)))
```
```python
def PKCS7_unpad(paddedtext: bytes) -> bytes:
    """
    Unpads the given text if it's padded according to PKCS7 norms.
    """
    
    # Checks if the text is padded according to PKCS7 norms.
    if PKCS7_padded(paddedtext):
        # The last byte is a padding byte.
        pad_Length = paddedtext[len(paddedtext)-1]
        # Returns the text uptil last "pad" length bytes since pad byte value is the same as number of pad bytes required.
        return paddedtext[:-pad_Length]
    else:
        return paddedtext
```
```python
def AES_CBC_decrypt(ciphertext: bytes, IV: bytes, key: bytes) -> bytes:
    """
    Decrypts a ciphertext encrypted with AES CBC Mode.
    AES ECB is the block cipher encryption of choice.
    Refer https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC) for the formulae.
    """
    previous = IV
    keysize = len(key)
    plaintext = b""
    cipher = ""
    
    for i in range(0, len(ciphertext), keysize):
        cipher = AES_ECB_decrypt(ciphertext[i:i+keysize], key)
        xor_list = [chr(b1 ^ b2) for b1, b2 in zip(cipher, previous)]
        plaintext += "".join(xor_list).encode()
        previous = ciphertext[i:i+keysize]
        
    return plaintext
```

!["CBC_decryption"](Set%202/1_image.png)
_AES CBC Decryption._

```python
def AES_CBC_decrypt(ciphertext: bytes, IV: bytes, key: bytes) -> bytes:
    """
    Decrypts a ciphertext encrypted with AES CBC Mode.
    AES ECB is the block cipher encryption of choice.
    Refer https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC) for the formulae.
    """
    previous = IV
    keysize = len(key)
    plaintext = b""
    cipher = ""
    
    for i in range(0, len(ciphertext), keysize):
        cipher = AES_ECB_decrypt(ciphertext[i:i+keysize], key)
        xor_list = [chr(b1 ^ b2) for b1, b2 in zip(cipher, previous)]
        plaintext += "".join(xor_list).encode()
        previous = ciphertext[i:i+keysize]
        
    return plaintext
```

We decrypt the message via our decryption function and run the deciphered text through the unpad function, just in case.
```python
byte_string = b"".join([base64.b64decode(line.strip()) for line in b64_data])

text = PKCS7_unpad(AES_CBC_decrypt(byte_string, b'\x00'*AES.block_size, key))
print(text.decode("utf-8").strip('\n'))
```

I'm back and I'm ringin' the bell 

A rockin' on the mike while the fly girls yell 

In ecstasy in the back of me 

Well that's my DJ Deshay cuttin' all them Z's 

Hittin' hard and the girlies goin' crazy 

Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 

It controls my mouth and I begin 

To just let it flow, let my concepts go 

My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 

And if you don't give a damn, then 

Why you starin' at me 

So get off 'cause I control the stage 

There's no dissin' allowed 

I'm in my own phase 

The girlies sa y they love me and that is ok 

And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 

It's off my head so let the beat play through 

So I can funk it up and make it sound good 

1-2-3 Yo -- Knock on some wood 

For good luck, I like my rhymes atrocious 

Supercalafragilisticexpialidocious 

I'm an effect and that you can bet 

I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 

There's no denyin', You can try to hang 

But you'll keep tryin' to get my style 

Over and over, practice makes perfect 

But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 

Soon -- Oh my God, homebody, you probably eat 

Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 

Intoxicating so you stagger like a wino 

So punks stop trying and girl stop cryin' 

Vanilla Ice is sellin' and you people are buyin' 

'Cause why the freaks are jockin' like Crazy Glue 

Movin' and groovin' trying to sing along 

All through the ghetto groovin' this here song 

Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 

Startled by the bases hittin' ground 

There's no trippin' on mine, I'm just gettin' down 

Sparkamatic, I'm hangin' tight like a fanatic 

You trapped me once and I thought that 

You might have it 

So step down and lend me your ear 

'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 

Your body's gettin' hot, so, so I can smell it 

So don't be mad and don't be sad 

'Cause the lyrics belong to ICE, You can call me Dad 

You're pitchin' a fit, so step back and endure 

Let the witch doctor, Ice, do the dance to cure 

So come up close and don't be square 

You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 

So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 

play that funky music Go white boy, go white boy, go 

Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 

Play that funky music white boy you say it, say it 

Play that funky music A little louder now 

Play that funky music, white boy Come on, Come on, Come on 

Play that funky music 

{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}



### Challenge 11: An ECB/CBC detection oracle
[Link](https://cryptopals.com/sets/2/challenges/11)

> Now that you have ECB and CBC working:  
> Write a function to generate a random AES key; that's just 16 random bytes.  
> Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.  
> The function should look like:  
> **encryption\_oracle(your-input)**  
> **\=> \[MEANINGLESS JIBBER JABBER\]**  
> Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.  
> Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use. Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.

```python
# Imports
import random
import os
from Crypto.Cipher import AES
```

The AES ECB Mode encryption function pads the plaintext message before encrypting it so as to make the plaintext length a multiple of block size, since it's a block mode cipher.

```python
def AES_ECB_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypts a plaintext with AES ECB Mode.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    text = PKCS7_pad(plaintext, len(key))
    return cipher.encrypt(PKCS7_pad(text, len(key)))
```

The second AES Mode is the **CBC** (**Cipher Block Chaining**) Mode. Each block of plaintext is XORed with the previous ciphertext block before being encrypted. This way, each ciphertext block depends on all plaintext blocks processed up to that point. To make each message unique, an **Initialization Vector** must be used in the first block.

!["CBC_encryption"](Set%202/2_image.png)
_AES CBC Encryption._

```python
def AES_CBC_encrypt(plaintext: bytes, IV: bytes, key: bytes) -> bytes:
    """
    Encrypts a plaintext with AES CBC Mode.
    AES ECB is the block cipher encryption of choice.
    Refer https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC) for the formulae.
    """
    previous = IV
    keysize = len(key)
    ciphertext = b""
    xored = b""
    
    for i in range(0, len(plaintext), keysize):
        xor_list = [(b1 ^ b2).to_bytes(1, "big") for b1, b2 in zip(PKCS7_pad(plaintext[i:i+keysize], keysize), previous)]
        xored = b"".join(xor_list)
        cipher = AES_ECB_encrypt(xored, key)
        ciphertext += cipher
        previous = cipher
        
    return ciphertext
```
```python
key = os.urandom(16)

# Enter a repeating text.
text = open("8.txt").read()

# Prepend and append random bytes to the text    
plaintext = os.urandom(random.randint(5,11))
plaintext += text.encode()
plaintext += os.urandom(random.randint(5,11))

flag = random.randint(0,1)
if flag == 1:
    print("Encrypting using AES ECB Encryption.")
    ciphertext = AES_ECB_encrypt(plaintext, key)
else:
    print("Encrypting using AES CBC Encryption.")
    ciphertext = AES_CBC_encrypt(plaintext, os.urandom(AES.block_size), key)
    
if detect_AES_ECB(ciphertext):
    print("Ciphertext is AES ECB encrypted.")
else:
    print("Ciphertext is AES CBC encrypted.")
```
Encrypting using AES CBC Encryption.
Ciphertext is AES CBC encrypted.

```python
test(True)
```
{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}



### Challenge 12: Byte-at-a-time ECB decryption (Simple)
[Link](https://cryptopals.com/sets/2/challenges/12)

> Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).  
> Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:  
> **Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg**  
> **aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq**  
> **dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg**  
> **YnkK**  
> Base64 decode the string before appending it.  
> Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.  
> What you have now is a function that produces:  
> **AES-128-ECB(your-string || unknown-string, random-key)**  
> It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!  
> Here's roughly how:

1.  Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
2.  Detect that the function is using ECB. You already know, but do this step anyways.
3.  Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
4.  Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
5.  Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
6.  Repeat for the next byte.

```python
# Imports
import os
import base64
import random
from Crypto.Cipher import AES
```
```python
# Given
b64_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
```
```python
# Generating a pseudo random key, to be run only once.
random_key = os.urandom(16)
```

The oracle as defined by the question.
```python
def AES128(text: bytes) -> bytes:
    """
    Oracle function to return ciphertext for secret string appended to plaintext.
    """
    global b64_string
    global random_key
    secret_string = base64.b64decode(b64_string)
    plaintext = text + secret_string
    cipher = AES_ECB_encrypt(plaintext, random_key)
    return cipher
```
```python
def AES_ECB_keysize(AES: callable) -> int:
    """
    Returns keysize used by an AES ECB encryption function.
    """
    
    text = "A random key long enough to decode the key size used in the encryption"
    
    # Checks repetition of blocks.
    # Looks for increase in cipher length because the moment text length goes over blocksize, a new block is created of blocksize, padded.
    # Thus we can infer block size from the increase in length observed.
    for i in range(1, len(text)):
        plaintext = text[:i] + text[:i]
        cipher = AES(plaintext.encode())
        if cipher[:i] == cipher[i:2*i]:                          
            print("Key size used for the given ciphertext is {}".format(i))
            return i
```

The function is based on the steps provided in the question itself. We send a (blocksize - 1) length input. Since the secret string gets appended to our input, the first byte of the secret string will become the last byte of the block of our input.

For example,

    let:    

        input = template,  

        plaintext be the final input we send for encryption,  

        block size = 4,  

        secret string = "scrt"  

    if length(template) == block size,  

        template = "AAAA"  

        plaintext = AAAA-scrt  

    with input(our template) being one byte short,  

        template = "AAA\_"  

            where, \_ is the byte we will be filling in while brute forcing  

        plaintext = AAAs-crt\\x01    (\\x01 is the pad byte)  

Therefore, to break this, we find the ciphertext for template = "AAA" and then run a comparsion against "AAAx", where x:=range(alphabets). Eventually, a comparison for "AAAs" will be made and it will return true. Thus, last byte has been decrypted.

What we have to keep in mind now is the fact that the discovered byte needs to be appended to the plaintext before we try to decrypt the next byte. The template would now be:

    template = "AAs\_"  

        where, \_ is the byte we will while brute forcing.

            s is the byte we discovered already.  

The previously discovered byte has to be added because:

    length(template) = block size - 2,  

    => template = "AA"  

       plaintext = AAsc-rt\\x02\\x02    (\\x02 are the pad bytes)  

Therefore, to break this, we find the ciphertext for template = "AAs" and then run a comparsion against "AAsx", where x:=range(alphabets). Eventually, a comparison for "AAsc" will be made and it will return true. Thus, two byte have now been decrypted.

This is done for the entirety of the secret string length.

```python
def break_AES_ECB(keysize: int, encryptor: callable) -> bytes:
    """
    Breaks AES ECB encryption for the encryptor function provided.
    """
    deciphered = b""
    
    # To get secret string length since 0 len input is provided, ciphertext only consists of secret string.
    ciphertext = encryptor(deciphered)
    # We run the loop upto the length of the secret string since that's what we have to discover.
    run = len(ciphertext)
    
    for i in range(1, run+1):
        # Template is 'A' multiplied by number of bytes not decrytpted yet.
        template = b'A'*(run - i)
        # Gets cipher for template
        cipher = encryptor(template)
        
        for j in range(256):
            # Adds the deciphered bytes to the template
            text = template + deciphered + j.to_bytes(1, "big")
            c = encryptor(text)
            # Keysize used to refer to the block whose last character is made to be the appended string's 1st char.
            # Comparison between letters appended to the last byte and the cipher of the template only.
            if c[run-keysize:run] == cipher[run-keysize:run]:
                deciphered += chr(j).encode()
                break
    
    return PKCS7_unpad(deciphered)
```

Get keysize to identify block size.
```python
keysize = AES_ECB_keysize(AES128)

# Decipher appended input.
deciphered = break_AES_ECB(keysize, AES128)
print("Given base64 encoded string was:\n\n{}".format(deciphered.decode("utf-8").strip('\n')))
```

Key size used for the given ciphertext is 16

Given base64 encoded string was:

Rollin' in my 5.0

With my rag-top down so my hair can blow

The girlies on standby waving just to say hi

Did you stop? No, I just drove by

```python
test(True)
```
{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}



### Challenge 13: ECB cut-and-paste
[Link](https://cryptopals.com/sets/2/challenges/13)

> Write a k=v parsing routine, as if for a structured cookie.  
> The routine should take:  
> **foo=bar&baz=qux&zap=zazzle**  
> ... and produce:  
> **{**  
> **foo: 'bar',**  
> **baz: 'qux',**  
> **zap: 'zazzle'**  
> **}**  
> (you know, the object; I don't care if you convert it to JSON).  
> Now write a function that encodes a user profile in that format, given an email address. You should have something like:  
> **profile\_for("foo@bar.com")**  
> ... and it should produce:  
> **{ email: 'foo@bar.com',**  
> **uid: 10,**  
> **role: 'user'**  
> **}**  
> ... encoded as:  
> **email=foo@bar.com&uid=10&role=user**  
> Your "profile\_for" function should not allow encoding metacharacters (& and =).  
> Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".  
> Now, two more easy functions. Generate a random AES key, then: Encrypt the encoded user profile under the key; "provide" that to the "attacker".  
> Decrypt the encoded user profile and parse it.  
> Using only the user input to profile\_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile

```python
# Imports
import os
from Crypto.Cipher import AES
```

A shot at decoding the string into the dictionary.
```python
string_set = "foo=bar&baz=qux&zap=zazzle"
dictionary = {key:val for key, val in (element.split('=') for element in string_set.split('&'))}
dictionary
```
{'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}

```python
# Generating a pseudo random key, to be run only once.
random_key = os.urandom(16)
```
```python
def parser(user: dict, encode: bool) -> dict:
    """
    Parse the given string into a dictionary of format User.
    """
    if encode == True:
        parsed_string =  "&".join(key.strip(":")+"="+val for key, val in zip(user.keys(), user.values()))
        return parsed_string.encode()
    else:
        return {key:val for key, val in (element.split('=') for element in user.split('&'))}
```
```python
def profile_for(val: str) -> dict:
    """
    Returns a user profile for given email.
    """
    val = val.decode("utf-8")
    user = {"email:": val, "uid:": "10", "role": "user"}
    return parser(user, True)
```

The oracle as defined by the question.
```python
def oracle(email: str) -> bytes:
    """
    Returns a new profile for the given email in AES ECB encrypted form.
    """
    encoded_profile = AES_ECB_encrypt(profile_for(email), random_key)
    return encoded_profile
```

Test if the oracle works.
```python
email = b"lol@gmail.com"
decoded_profile = PKCS7_unpad(AES_ECB_decrypt(oracle(email), random_key))
profile = parser(decoded_profile.decode("utf-8"), False)
decoded_profile.decode("utf-8")
```
'email=lol@gmail.com&amp;amp;amp;amp;amp;amp;amp;uid=10&amp;amp;amp;amp;amp;amp;amp;role=user\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c'

The idea here is to get the encrypted bytes of the parameter("admin") we have to write into the string, and then insert those bytes as is into a benign ciphertext.

We generate an email as follows:  
We fill garbage value uptil the starting block(since "email=" is at the beginning of the string) is completed and then append the parameter("admin") in a padded state so that we get a fresh, whole block of the parameter encrypted.

Now we inject this into the string as follows:  
We input an email such that "&role=" are the last bytes of a block and "user" comes in a new block(would be the last block since "user" is at the end of the string). This last block is replaced by the block of cipher we generated for the parameter.

```python
keysize = 16

# Get encrypted bytes with "admin".
email = b"f"*(keysize-len("email=")) + PKCS7_pad(b"admin", keysize)
cipher = oracle(email)
encoded_admin_bytes = cipher[keysize:keysize*2]

# Calculate the number of blocks taken up by the text and then generate an email that completes the block so the admin parameter can be appended in the new block.
num_blocks = int((len("&uid=10") + len("email=") + len("&role="))/keysize) + 1
email = b"f"*(num_blocks*keysize - (len("&uid=10") + len("email=") + len("&role=")-6))+b"@gmail.com"
cipher = oracle(email)
# Add the encoded paramter bytes to the ciphertext.
modified_cipher = cipher[:48] + encoded_admin_bytes

cracked_cipher_plaintext = parser(PKCS7_unpad(AES_ECB_decrypt(modified_cipher, random_key)).decode("utf-8"), False)
```

```python
test(cracked_cipher_plaintext['role'] == 'admin')
```
{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}



### Challenge 14: Byte-at-a-time ECB decryption (Harder)
[Link](https://cryptopals.com/sets/2/challenges/14)

> Take your oracle function from #12.  
> Now generate a random count of random bytes and prepend this string to every plaintext.  
> You are now doing:  
> **AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)**  
> Same goal: decrypt the target-bytes.

```python
# Imports
import os
import math
import base64
import random
from Crypto.Cipher import AES
```
```python
# Given
b64_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
```
```python
# Pseudo random key and prefix string.
random_key = os.urandom(16)
random_string = os.urandom(random.randint(0,255))
```

The oracle as defined by the question. Only difference from #12 is that it prepends the text with random string of fixed length.
```python
def AES128_harder(text: bytes) -> bytes:
    """
    Oracle function to return ciphertext for random string and secret string, prepended and appended respectively, to plaintext.
    """
    global b64_string, random_key, random_string
    
    secret_string = base64.b64decode(b64_string)
    plaintext = random_string + text + secret_string
    cipher = AES_ECB_encrypt(plaintext, random_key)
    return cipher
```

We need to account for the random string being prepended. If it wasn't there, this question would be the exact same as #12(a secret string being appended to our input).  
Therefore, if we were to neutralise this random string, we can follow the same approach as that of #12.

We find out the random string's length by calculating the common prefix appended in every ciphertext. This common prefix is the random string. We get it's length.  
We then find out the number of blocks it's taking and how much padding we need so that our input is put into a new block when being encrypted.  
Once we are able to reach the point where the input begins in a new block, we can say that the random string has been neutralised, making this question essentially the same as #12.

```python
def break_AES_ECB_harder(keysize: int, encryptor: callable) -> bytes:
    """
    Breaks AES ECB encryption for the encryptor function provided.
    """
        
    # Find the prefix length.
    padding = 0
    random_blocks = 0
    cipher_length = len(encryptor(b''))
    prefix_length = len(os.path.commonprefix([encryptor(b'AAAA'), encryptor(b'')]))
    print("Prefix length: ", prefix_length)
    
    # Find number of random blocks.
    for i in range(int(cipher_length/keysize)):
        if prefix_length < i*keysize:
            random_blocks = i
            break
    print("Random blocks: ", random_blocks)
    
    # Find number of byte padding required.
    base_cipher = encryptor(b'')
    for i in range(1, keysize):
        new_cipher = encryptor(b'A'*i)
        new_prefix_length = len(os.path.commonprefix([base_cipher, new_cipher]))
        if new_prefix_length > prefix_length:
            padding = i - 1
            break
        base_cipher = new_cipher
    print("Number of bytes of padding required: ", padding)
    
    # To get added string length since 0 len input is provided, all cipher is of added string.
    deciphered = b""
    ciphertext = encryptor(deciphered)
    # Because of one block increase due to addition of padding.
    run = len(ciphertext) + keysize
    
    # Should start after prefix random_blocks because till then it value will be same for original cipher and templated cipehr since same prepended string will be compared.
    for i in range(keysize * random_blocks + 1, run+1):
        template = b'A'*(run - i + padding)
        cipher = encryptor(template)
        for j in range(256):
            #print(i, j)
            text = template + deciphered + j.to_bytes(1, "little")
            c = encryptor(text)
            # Keysize used to refer to the block whose last character is made to be the appended string's 1st char.
            if c[run-keysize:run] == cipher[run-keysize:run]:
                deciphered += chr(j).encode()
                break
    return PKCS7_unpad(deciphered)
```
```python
keysize = 16
byte_text = break_AES_ECB_harder(keysize, AES128_harder)
print("\nDeciphered string:\n")
print(byte_text.decode("utf-8").strip())
```
Prefix length:  176
Random blocks:  12
Number of bytes of padding required:  4
Deciphered string:

Rollin' in my 5.0

With my rag-top down so my hair can blow

The girlies on standby waving just to say hi

Did you stop? No, I just drove by

```python
test(True)
```
{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}



### Challenge 15: PKCS#7 padding validation
[Link](https://cryptopals.com/sets/2/challenges/15)

> Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.  
> The string:  
> **"ICE ICE BABY\\x04\\x04\\x04\\x04"**  
> ... has valid padding, and produces the result "ICE ICE BABY".  
> The string:  
> **"ICE ICE BABY\\x05\\x05\\x05\\x05"**  
> ... does not have valid padding, nor does:  
> **"ICE ICE BABY\\x01\\x02\\x03\\x04"**  
> If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.  
> Crypto nerds know where we're going with this. Bear with us.

```python
# Given
given_string = "ICE ICE BABY\x04\x04\x04\x04"
target_string = "ICE ICE BABY"
```

We can use our good old PKCS7\_unpad function.

```python
test(target_string.encode() == PKCS7_unpad(given_string.encode()))
```
{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}



### Challenge 16: CBC bitflipping attacks
[Link](https://cryptopals.com/sets/2/challenges/16)

> Generate a random AES key.  
> Combine your padding code and CBC code to write two functions.  
> The first function should take an arbitrary input string, prepend the string:  
> **"comment1=cooking%20MCs;userdata="**  
> .. and append the string:  
> **";comment2=%20like%20a%20pound%20of%20bacon"**  
> The function should quote out the ";" and "=" characters.  
> The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.  
> The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).  
> Return true or false based on whether the string exists.  
> If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.  
> Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.  
> You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

*   Completely scrambles the block the error occurs in.
*   Produces the identical 1-bit error(/edit) in the next ciphertext block.

```python
# Imports
import os
import random
from Crypto.Cipher import AES
```
```python
# Given
prepend_string = "comment1=cooking%20MCs;userdata="
append_string = ";comment2=%20like%20a%20pound%20of%20bacon"
parameter = b";admin=true;"
```
```python
keysize = 16
random_key = os.urandom(keysize)
IV = os.urandom(random.randint(0,255))
```

The first function:

*   Appends the string.
*   Quotes out the specified characters.
*   Pads the input and encrypts it with AES CBC.
```python
def encryptor(text: bytes, IV: bytes, key: bytes) -> bytes:
    """
    Prepend and append the given strings to custom text, and encrypt via AES CBC Mode.
    """
    plaintext =  (prepend_string.encode() + text + append_string.encode()).replace(b';', b'";"').replace(b'=', b'"="')
    ciphertext = AES_CBC_encrypt(PKCS7_pad(plaintext, len(key)), IV, key)
    return ciphertext
```

The second function:

*   Decrypts the input.
*   Returns true or false based on presence of ";admin=true;" in the decrypted string.
```python
def decryptor(byte_string: bytes, IV: bytes, key: bytes) -> bool:
    """
    Decrypt the given ciphertext via AES CBC Mode and check if admin is set to true.
    """
    decrypted_string = PKCS7_unpad(AES_CBC_decrypt(byte_string, IV, key))
    if b";admin=true;" in decrypted_string:
        return True
    else:
        return False
```

During AES CBC Mode decryption process, decryption of ith block involves xoring it with (i-1)th block.  
The trick here is the fact that the change you make to the bit of (i-1)th block, is the exact same change that's going to be reflected in the decrypyted text of ith block. This is because both the blocks are being xored together.

The thing to note here is that flipping the bit of (i-1)th block is going to completely distort the decrypted text of (i-1)th block. But this is not an issue since we are focusing on the decryption of ith block.

We therefore modify the bits of (i-1)th block by xoring it together with the given string so as to produce values, that when xored with ith block, give out this string.

For example,   
	let:        
		ciphertext_block_1 = “xxxx”        
		ciphertext_block_2 = “efgh”        
		=> plaintext_block_2 = AES_ECB_decrypt("abcd") ⊕ “xxxx”

If we change ciphertext_block_1 to “xxbx”, plaintext_block_2 becomes AES_ECB_decrypt("abcd") ⊕ “xxbx”, i.e only the 3rd position changes.

Assume plaintext_block_2 = “cats”. Now, if we want to change it to "cots", we need to find a byte “y” such that we can change ciphertext_block_1 to “xyxx” and get “cots” as plaintext_block_2.

AES_ECB_decrypt("efgh") ⊕ “xxxx” = “cats”
AES_ECB_decrypt("efgh") ⊕ “xyxx” = “cots”

Let’s say f∗ is the AES ECB decrypted “f”. Also, the inverse of XOR is XOR.

    f∗⊕x=“i”    
    f∗=x⊕“i”    
    f∗⊕y=“o”    
    y=f∗⊕“a”=x⊕“i”⊕“a”

```python
def CBC_bit_flipping(parameter: bytes, keysize: int, encryptor: callable) -> bytes:    
    
    # Padding required to bridge gap between randomstringlength and block.
    padding = 0
    random_blocks = 0


    # Find the prefix length.
    cipher_length = len(encryptor(b'', IV, random_key))
    prefix_length = len(os.path.commonprefix([encryptor(b'AAAA', IV, random_key), encryptor(b'', IV, random_key)]))
    print("Prefix length: ", prefix_length)

    # Find number of random blocks.
    for i in range(int(cipher_length/keysize)):
        if prefix_length < i*keysize:
            random_blocks = i
            break
    print("Random blocks: ", random_blocks)

    # Find number of byte padding required.
    base_cipher = encryptor(b'', IV, random_key)
    for i in range(1, keysize):
        new_cipher = encryptor(b'A'*i, IV, random_key)
        new_prefix_length = len(os.path.commonprefix([base_cipher, new_cipher]))
        if new_prefix_length > prefix_length:
            padding = i - 1
            break
        base_cipher = new_cipher
    print("Number of bytes of padding required: ", padding)

    # Flip bytes for the given string.
    input_text = b'A'*padding + b"heytheremama"
    string = parameter
    modified_string = b""
    ciphertext = encryptor(input_text, IV, random_key)
    for i in range(len(string)):
        modified_string += (ciphertext[i+(random_blocks-1)*keysize]^(input_text[i+padding]^string[i])).to_bytes(1, "big")

    modified_ciphertext = ciphertext[:(random_blocks-1)*keysize] + modified_string + ciphertext[(random_blocks-1)*keysize + len(modified_string):]
    
    return modified_ciphertext
```
```python
modified_ciphertext = CBC_bit_flipping(parameter, keysize, encryptor)
AES_CBC_decrypt(modified_ciphertext, IV, random_key)
```
Prefix length:  32
Random blocks:  3
Number of bytes of padding required:  7

b'comment1"="cooking%20MCs";"userd\\t\\xc2\\xaf\\xc3\\x8c\\xc2\\x8a\\xc3\\xa6\\xc3\\x9e\\xc2\\x94\\xc3\\x989;\\xc2\\x97\\xc3\\xa3\\xc2\\xb1s#\\xc2\\x94;admin=true;";"comment2"="%20like%20a%20pound%20of%20bacon\\x06\\x06\\x06\\x06\\x06\\x06'

```python
test(decryptor(modified_ciphertext, IV, random_key) == True)
```
{{< rawhtml >}}
<div style="border:1px solid #c3e6cb;padding:.75rem 3rem;border-radius:.5rem;font-weight:bold;text-align: center;background-color:#d4edda;color:#155724;border-color:#c3e6cb;">Completed</div>
{{< /rawhtml >}}

