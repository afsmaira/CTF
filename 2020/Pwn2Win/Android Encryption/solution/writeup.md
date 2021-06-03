# Android Encryption

At script beginning, there is the following expression:

```python3
iv2 = AES.new(key1, AES.MODE_ECB).decrypt(iv1)
``` 
that is the decryption of the random initialization vector that encrypts the given plaintext.

Analysing the script, we can see that function `encrypt()` encrypts using AES method in PCBC mode and makes `key2`, which encrypts the flag, be all encrypted blocks xor. Using that function, we take control of `key2` value, especially if we get a ciphertext where all blocks are the same, so the key will be null.

Let's analyse the diagram of this mode in [wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC)), starting by setting each ciphertext block `C[i] = C`. In this way, for first plaintext block, we have:

```python3
P[1] = decrypt(C[1]) ^ iv 
P[1] = decrypt(C) ^ iv
```

For second plaintext block:

```python3
P[2] = decrypt(C[2]) ^ (P[1] ^ C[1])
P[2] = decrypt(C) ^ (decrypt(C) ^ iv ^ C)
P[2] = (decrypt(C) ^ decrypt(C)) ^ iv ^ C
P[2] = C ^ iv
```

So:

```python3
P[1] ^ P[2] = (decrypt(C) ^ iv) ^ (C ^ iv) = iv ^ decrypt(iv)
```

Calling `iv1 = iv` in script, we have `iv2 = decrypt(iv)`, so the plaintext blocks must obey `P[1] ^ P[2] = iv1 ^ iv2`. Both `iv2` and `iv1`, we can obtain from beginning of flag encryption (option 2) and any plaintext encryption (option 1), respectively. But we do not have `C`, but we can control it by controlling `P[2]`. Making `P[2] = 0`, we have `C = iv1` and `P[1] = iv1 ^ iv2`.

Let's make the solution. Let's start by getting `iv2` using the option 2:

```python3
iv2 = cipherflag[:16]
```

Now we can get the `iv1` using the option 1 with any plaintext with size multiple of 16, for example, `16*'a'`:

```python3
iv1 = ciphertext[:16]
```

With initialization vectors, we can prepare the plaintext:

```python3
txt = xor(iv1, iv2) + 16*b'\x00'
```

Using this plaintext in option 1 we make the `key2`, used to encrypt the flag, be null. At last, we use the option 2 to encrypt the flag. Now we have `cipherflag`, `key2` and `iv2`. By implementing the AES PCBC decrypt function, we get the flag:

```python3
import base64

from pwn import *
from Crypto.Cipher import AES

host = "encryption.pwn2.win"
port = 1337


def xor(b1, b2=None):
    if isinstance(b1, list) and b2 is None:
        assert len(set([len(b) for b in b1])) == 1, 'xor() - Invalid input size'
        assert all([isinstance(b, bytes) for b in b1]), 'xor() - Invalid input type'
        x = [len(b) for b in b1][0]*b'\x00'
        for b in b1:
            x = xor(x, b)
        return x
    assert isinstance(b1, bytes) and isinstance(b2, bytes), 'xor() - Invalid input type'
    return bytes([a ^ b for a, b in zip(b1, b2)])


def to_blocks(txt):
    return [txt[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(len(txt)//BLOCK_SIZE)]


def decrypt(enc, key, iv):
    assert len(key) == BLOCK_SIZE
    assert len(iv) == BLOCK_SIZE
    blocks = to_blocks(enc)
    txt = b''
    aes = AES.new(key, AES.MODE_ECB)
    for block in blocks:
        txt += xor(iv, aes.decrypt(block))
        iv = xor(txt[-BLOCK_SIZE:], block)
    return txt


flag_fmt = b'CTF-BR'


BLOCK_SIZE = 16


conn = remote(host, port)
# conn = process(['./server.py'])
conn.recvuntil('Choice: ')
# 2 - iv2
conn.sendline('2')
data = conn.recvuntil('Choice: ')
data = base64.b64decode(data.split(b'\nMENU')[0])
iv2 = data[:BLOCK_SIZE]
print(f'iv2 {iv2}')
# 1 - iv1, txt
conn.sendline('1')
conn.recvuntil('Plaintext: ')
conn.sendline(base64.b64encode(16*b'a'))
data = conn.recvuntil('Choice: ')
data = base64.b64decode(data.split(b'\nMENU')[0])
iv1 = data[:BLOCK_SIZE]
print(f'iv1 {iv1}')
txt = xor(iv1, iv2)+BLOCK_SIZE*b'\x00'
print(f'txt {txt}')
# 1 - key2 = 0
conn.sendline('1')
conn.recvuntil('Plaintext: ')
conn.sendline(base64.b64encode(txt))
data = conn.recvuntil('Choice: ')
data = base64.b64decode(data.split(b'\nMENU')[0])
iv1 = data[:BLOCK_SIZE]
ctxt = data[BLOCK_SIZE:]
key = xor(to_blocks(ctxt))
print(f'key2 {key}')
# 2 - cflag
conn.sendline('2')
data = conn.recvuntil('Choice: ')
data = base64.b64decode(data.split(b'\nMENU')[0])
iv = data[:BLOCK_SIZE]
cflag = data[BLOCK_SIZE:]
conn.sendline('3')
print(f'cflag {cflag}')
print(decrypt(cflag, key, iv))
```

With output:

```python3
b'CTF-BR{kn3W_7h4T_7hEr3_4r3_Pc8C_r3pe471ti0ns?!?}'
```
