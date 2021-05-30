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
