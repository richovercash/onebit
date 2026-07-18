#!/usr/bin/env python3
"""Generate Prover.toml for bench_monolithic and bench_presentation."""
import hashlib, os, secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
P_BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def limbs(x, n=18, bits=120):
    return ['0x%x' % ((x >> (bits * i)) & ((1 << bits) - 1)) for i in range(n)]

def arr(bs):
    return '[' + ', '.join(str(b) for b in bs) + ']'

# --- document data ---
mrz = ('P<UTODOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<'
       'L898902C36UTO8001014M3102252<<<<<<<<<<<<<<06')
assert len(mrz) == 88, len(mrz)
dg1 = b'\x61\x5b\x5f\x1f\x58' + mrz.encode()
assert len(dg1) == 93
# dob at mrz[57:63]=800101, expiry at mrz[65:71]=310225
assert mrz[57:63] == '800101' and mrz[65:71] == '310225', (mrz[57:63], mrz[65:71])

econtent = bytearray(secrets.token_bytes(1200))
econtent[100:132] = hashlib.sha256(dg1).digest()
econtent = bytes(econtent)

dsc_cert = secrets.token_bytes(1000)

# --- RSA-2048 PKCS#1 v1.5 / SHA-256 over econtent ---
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
sig = key.sign(econtent, padding.PKCS1v15(), hashes.SHA256())
n = key.public_key().public_numbers().n
sig_int = int.from_bytes(sig, 'big')
redc = (1 << (2 * 2048 + 6)) // n

# --- misc witness ---
merkle_path = [secrets.randbelow(P_BN254) for _ in range(20)]
k = secrets.randbelow(P_BN254)
ctx = secrets.randbelow(P_BN254)
salt = secrets.randbelow(P_BN254)
current, age_min = 20260711, 18

def q(xs):
    return '[' + ', '.join('"%s"' % x for x in xs) + ']'

with open(os.path.join(HERE, 'monolithic', 'Prover.toml'), 'w') as f:
    f.write(f'''dg1 = {arr(dg1)}
econtent = {arr(econtent)}
dsc_cert = {arr(dsc_cert)}
sig = {q(limbs(sig_int))}
modulus = {q(limbs(n))}
redc = {q(limbs(redc))}
merkle_path = {q(merkle_path)}
merkle_dirs = 349525
k = "{k}"
ctx = "{ctx}"
current = {current}
age_min = {age_min}
''')

doc_hash = secrets.randbelow(P_BN254)
with open(os.path.join(HERE, 'presentation', 'Prover.toml'), 'w') as f:
    f.write(f'''dob = 19800101
expiry = 20310225
doc_hash = "{doc_hash}"
k = "{k}"
salt = "{salt}"
ctx = "{ctx}"
current = {current}
age_min = {age_min}
''')

print('Prover.toml written for both circuits')
