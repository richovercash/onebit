#!/usr/bin/env python3
# Split a noir-rs proof file [BE uint32 num_public][pub*32][proof] into the
# {proof, publicInputs} JSON that verifier/js/verify.mjs reads on stdin.
# Usage: split_proof.py <proof.bin> <num_public>  ->  JSON on stdout
import base64, json, sys, pathlib

b = pathlib.Path(sys.argv[1]).read_bytes()
npub = int(sys.argv[2])
pubs = ['0x' + b[4 + i * 32:4 + (i + 1) * 32].hex() for i in range(npub)]
proof = b[4 + npub * 32:]
print(json.dumps({'proof': base64.b64encode(proof).decode(), 'publicInputs': pubs}))
