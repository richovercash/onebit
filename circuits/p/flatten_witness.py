#!/usr/bin/env python3
# Flatten circuits/p/Prover.toml into the native prover's witness format:
# one field per line, DECIMAL, in main()'s declaration order, arrays expanded,
# pub inputs included (same shape as app/.../assets/zk/wit_slim.txt).
# Lets the on-device native bench prove Circuit P v1 and time it (P1.0 spike).
import re, pathlib

ORDER = ["e_vkey", "e_proof", "c", "root_e", "dob", "expiry", "doc_hash",
         "k", "salt", "e_vkey_hash", "r_icao", "ctx", "current", "age_min"]

def dec(s):
    s = s.strip().strip('"')
    return str(int(s, 16) if s.lower().startswith("0x") else int(s))

text = pathlib.Path("Prover.toml").read_text()
out = []
for key in ORDER:
    # key = [ ... ]  (array)  OR  key = value  (scalar), value may be quoted.
    m = re.search(rf'^{key}\s*=\s*(\[.*?\]|"[^"]*"|\S+)', text, re.M | re.S)
    if not m:
        raise SystemExit(f"missing key: {key}")
    raw = m.group(1)
    if raw.startswith("["):
        out.extend(dec(x) for x in re.findall(r'"?(0x[0-9a-fA-F]+|\d+)"?', raw))
    else:
        out.append(dec(raw))

# Sanity: 115 vkey + 500 proof + 12 scalars = 627 fields.
assert len(out) == 627, f"expected 627 witness fields, got {len(out)}"
pathlib.Path("target/wit_p.txt").write_text("\n".join(out) + "\n")
print(f"wrote target/wit_p.txt: {len(out)} fields")
