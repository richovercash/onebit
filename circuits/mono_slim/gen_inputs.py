#!/usr/bin/env python3
"""Prover.toml for mono_slim — real-sized eContent, RSA-2048 signed."""
import hashlib, os, secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
H_OFF = 30

def limbs(x, n=18, bits=120):
    return ['0x%x' % ((x >> (bits * i)) & ((1 << bits) - 1)) for i in range(n)]

def arr(bs): return '[' + ', '.join(str(b) for b in bs) + ']'
def q(xs): return '[' + ', '.join('"%s"' % x for x in xs) + ']'

mrz = ('P<UTODOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<'
       'L898902C36UTO8001014M3102252<<<<<<<<<<<<<<06')
dg1 = b'\x61\x5b\x5f\x1f\x58' + mrz.encode()
assert len(dg1) == 93 and mrz[57:63] == '800101' and mrz[65:71] == '310225'

econtent = bytearray(secrets.token_bytes(256))
econtent[H_OFF:H_OFF + 32] = hashlib.sha256(dg1).digest()
econtent = bytes(econtent)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
sig = key.sign(econtent, padding.PKCS1v15(), hashes.SHA256())
n = key.public_key().public_numbers().n
redc = (1 << (2 * 2048 + 6)) // n

merkle_path = [secrets.randbelow(P) for _ in range(20)]
with open(os.path.join(HERE, 'Prover.toml'), 'w') as f:
    f.write(f'''dg1 = {arr(dg1)}
econtent = {arr(econtent)}
sig = {q(limbs(int.from_bytes(sig, "big")))}
modulus = {q(limbs(n))}
redc = {q(limbs(redc))}
merkle_path = {q(merkle_path)}
merkle_dirs = 349525
k = "{secrets.randbelow(P)}"
ctx = "{secrets.randbelow(P)}"
current = 20260718
age_min = 18
''')
print('mono_slim Prover.toml written')
