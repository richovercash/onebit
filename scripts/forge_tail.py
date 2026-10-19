#!/usr/bin/env python3
"""Negative fixtures for the hashed-prefix offset bounds (self-review N1/F1).

Witness offsets that point past the hashed length (*_len) land in array bytes
sha256_var never hashes, i.e. free witness. These forgeries plant data there
while the signature stays genuine; the circuits must REFUSE them.

  forge_tail.py mono <Prover.toml> <out.toml>   forged DG1, hash planted in econtent tail
  forge_tail.py enroll <Prover.toml> <out.toml> DSC key window moved into dsc_tbs tail
"""
import re, sys, hashlib, tomllib

mode, src, dst = sys.argv[1:4]
t = tomllib.load(open(src, "rb"))
text = open(src).read()

def setarr(name, vals):
    global text
    text = re.sub(rf'^{name} = \[.*?\]', f'{name} = [' + ", ".join(f'"{v}"' for v in vals) + ']',
                  text, count=1, flags=re.M | re.S)

def setscalar(name, v):
    global text
    text, k = re.subn(rf'^{name} = .*$', f'{name} = "{v}"', text, count=1, flags=re.M)
    assert k == 1, name

if mode == "mono":
    dg1 = [int(x) for x in t["dg1"]]
    dg1[62:68] = list(b"000101")                  # rewrite DOB (MRZ_OFF + 57)
    ec = [int(x) for x in t["econtent"]]
    n = int(t["econtent_len"])
    ec[n:n + 32] = list(hashlib.sha256(bytes(dg1)).digest())
    setarr("dg1", dg1); setarr("econtent", ec); setscalar("dg1_hash_off", n)
elif mode == "enroll":
    tbs = [int(x) for x in t["dsc_tbs"]]
    n, mo = int(t["dsc_tbs_len"]), int(t["dsc_modulus_off"])
    tbs[n:n + 256] = tbs[mo:mo + 256]
    setarr("dsc_tbs", tbs); setscalar("dsc_modulus_off", n)
else:
    sys.exit("mode: mono | enroll")
open(dst, "w").write(text)
