// Build the real CSCA Merkle tree (RSA-4096 variant) over the bundled master
// list, matching the enroll circuit: leaf = Poseidon2(35 modulus limbs),
// depth 10. Emits cscatree_rsa4096.json = { root, depth, paths: {spki_sha256:
// {dirs, path[10]}} } for the wallet to look up its CSCA's path.
import { BarretenbergSync } from '@aztec/bb.js';
import { execSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import { createHash } from 'crypto';

const api = await BarretenbergSync.initSingleton();
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DEPTH = 10;
const frBuf = (v) => { let b = Buffer.alloc(32); let x = ((BigInt(v) % P) + P) % P; for (let i = 31; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const pos = (arr) => BigInt('0x' + Buffer.from(api.poseidon2Hash({ inputs: arr.map(frBuf) }).hash).toString('hex'));

const pem = readFileSync('./masterlist.pem', 'utf8');
const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
const leaves = [], spki = [];
for (const b of blocks) {
  let mod;
  try { mod = execSync('openssl x509 -noout -modulus', { input: b, stdio: ['pipe','pipe','ignore'] }).toString().trim(); }
  catch (e) { continue; }                                       // ECDSA / non-RSA
  const m = mod.match(/^Modulus=([0-9A-Fa-f]+)$/);
  if (!m) continue;
  const n = BigInt('0x' + m[1]);
  if (n.toString(2).length > 4096) continue;                   // fits the 35-limb/4096 circuit (RSA 2048/3072/4096)
  const limbs = []; let x = n; const mask = (1n << 120n) - 1n;
  for (let i = 0; i < 35; i++) { limbs.push(x & mask); x >>= 120n; }
  leaves.push(pos(limbs));
  // SPKI sha256 (DER of SubjectPublicKeyInfo) as the lookup key
  const der = execSync('openssl x509 -noout -pubkey', { input: b }).toString();
  const spkiDer = Buffer.from(der.split('\n').filter(l => !l.includes('---')).join(''), 'base64');
  spki.push(createHash('sha256').update(spkiDer).digest('hex'));
}
const N = 1 << DEPTH;
const zero = 0n;
while (leaves.length < N) { leaves.push(zero); spki.push(null); }

// build layers
const layers = [leaves];
while (layers[layers.length - 1].length > 1) {
  const cur = layers[layers.length - 1], nx = [];
  for (let i = 0; i < cur.length; i += 2) nx.push(pos([cur[i], cur[i + 1]]));
  layers.push(nx);
}
const root = layers[layers.length - 1][0];

// paths per real CSCA
const paths = {};
for (let idx = 0; idx < N; idx++) {
  if (!spki[idx]) continue;
  const path = []; let i = idx;
  for (let d = 0; d < DEPTH; d++) { const sib = i ^ 1; path.push('0x' + layers[d][sib].toString(16)); i >>= 1; }
  paths[spki[idx]] = { dirs: idx, path };
}
const out = { root: '0x' + root.toString(16), depth: DEPTH,
  count: Object.keys(paths).length, paths };
writeFileSync('./cscatree_rsa4096.json', JSON.stringify(out));
console.log('RSA-4096 CSCAs:', out.count, '| depth', DEPTH, '| root', out.root);
process.exit(0);
