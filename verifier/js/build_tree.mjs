// Build the real CSCA Merkle trees over the bundled master list -- one tree per
// enroll-circuit algorithm, each with that circuit's EXACT leaf construction and
// depth 10. Emits cscatree_<alg>.json = { root, depth, count, paths:
// {spki_sha256: {dirs, path[10]}} } for the wallet, plus csca_roots.json.
//
//   rsa4096      enroll            leaf = Poseidon2(35 modulus limbs)   RSA <=4096
//   rsa6144      enroll_rsa6144    leaf = Poseidon2(52 modulus limbs)   RSA 4097-6144
//   brainpool256 enroll_ecdsa      leaf = Poseidon2(x||y as 4x16B)      256-bit EC
//   p384         enroll_p384       leaf = Poseidon2(x||y as 6x16B)      secp384r1
import { BarretenbergSync } from '@aztec/bb.js';
import { execSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import { createHash } from 'crypto';

const api = await BarretenbergSync.initSingleton();
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DEPTH = 10;
const frBuf = (v) => { let b = Buffer.alloc(32); let x = ((BigInt(v) % P) + P) % P; for (let i = 31; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const pos = (arr) => BigInt('0x' + Buffer.from(api.poseidon2Hash({ inputs: arr.map(frBuf) }).hash).toString('hex'));
const beInt = (buf) => { let x = 0n; for (const b of buf) x = (x << 8n) + BigInt(b); return x; };

// Minimal DER: read tag/length at off. Used to pull the REAL subjectPublicKey
// BIT STRING out of the SPKI (the trailing bytes are unreliable for explicit-
// param EC keys, whose inlined generator point also starts with 0x04).
function tlv(buf, off) {
  let i = off + 1, len = buf[i++];
  if (len & 0x80) { let nb = len & 0x7f; len = 0; while (nb-- > 0) len = (len << 8) | buf[i++]; }
  return { tag: buf[off], hEnd: i, end: i + len };
}
// -> {x, y} Buffers, or null if not an uncompressed EC point.
function ecPoint(spki) {
  const seq = tlv(spki, 0);            // SPKI SEQUENCE
  const alg = tlv(spki, seq.hEnd);     // AlgorithmIdentifier
  const bs = tlv(spki, alg.end);       // subjectPublicKey BIT STRING
  if (bs.tag !== 0x03) return null;
  const pt = spki.subarray(bs.hEnd + 1, bs.end); // skip the unused-bits byte
  if (pt[0] !== 0x04 || (pt.length - 1) % 2 !== 0) return null;
  const c = (pt.length - 1) / 2;
  return { x: pt.subarray(1, 1 + c), y: pt.subarray(1 + c) };
}

// leaf = Poseidon2 over n's little-endian 120-bit limbs (matches the RSA enroll circuits)
const rsaLeaf = (n, nlimbs) => { const limbs = []; let x = n; const mask = (1n << 120n) - 1n; for (let i = 0; i < nlimbs; i++) { limbs.push(x & mask); x >>= 120n; } return pos(limbs); };
// leaf = Poseidon2 over x then y, each split into big-endian 16-byte chunks
// (matches the ECDSA enroll circuits). x and y are packed SEPARATELY so a
// coordinate whose length isn't a multiple of 16 (P-521 = 66B) chunks correctly.
const ecLeaf = (x, y) => { const chunks = []; for (const c of [x, y]) for (let o = 0; o < c.length; o += 16) chunks.push(beInt(c.subarray(o, o + 16))); return pos(chunks); };

const T = { rsa4096: { leaves: [], spki: [] }, rsa6144: { leaves: [], spki: [] },
            brainpool256: { leaves: [], spki: [] }, p384: { leaves: [], spki: [] },
            secp256: { leaves: [], spki: [] }, bp384: { leaves: [], spki: [] },
            secp521: { leaves: [], spki: [] }, bp512: { leaves: [], spki: [] } };

// Field prime -> tree bucket (each bucket = one enroll circuit). Compared as
// BigInts (robust to leading-zero / sign-byte quirks). openssl prints an
// "ASN1 OID:" only for named curves; brainpool/some NIST CSCAs inline the params.
const CURVE = [
  { b: 'brainpool256', p: 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377n },
  { b: 'secp256',      p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn },
  { b: 'bp384',        p: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53n },
  { b: 'p384',         p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn },
  { b: 'secp521',      p: (1n << 521n) - 1n },
  { b: 'bp512',        p: 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3n },
];
const byPrime = new Map(CURVE.map(c => [c.p, c.b]));
const NAMED = { prime256v1: 'secp256', secp256r1: 'secp256', secp384r1: 'p384', prime384v1: 'p384', secp521r1: 'secp521', prime521v1: 'secp521' };
// Bucket an EC cert by its exact curve, or null if we have no circuit for it.
function ecBucket(txt) {
  const oid = (txt.match(/ASN1 OID: (\S+)/) || [])[1];
  if (oid) return NAMED[oid] || 'named:' + oid;
  const pm = txt.match(/Prime:\n((?:\s+[0-9a-f:]+\n)+)/); // lowercase hex lines
  if (!pm) return null;
  let h = pm[1].replace(/[\s:]/g, '');
  return byPrime.get(BigInt('0x' + h)) || 'ec-' + (h.length * 4) + 'bit';
}
const uncovered = {};

const pem = readFileSync('./masterlist.pem', 'utf8');
const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
let skipped = 0;
for (const b of blocks) {
  let spkiDer;
  try { const der = execSync('openssl x509 -noout -pubkey', { input: b }).toString(); spkiDer = Buffer.from(der.split('\n').filter(l => !l.includes('---')).join(''), 'base64'); }
  catch { skipped++; continue; }
  const id = createHash('sha256').update(spkiDer).digest('hex');

  // RSA: bucket by modulus bit length.
  let mod = null;
  try { mod = execSync('openssl x509 -noout -modulus', { input: b, stdio: ['pipe', 'pipe', 'ignore'] }).toString().trim(); } catch {}
  const mm = mod && mod.match(/^Modulus=([0-9A-Fa-f]+)$/);
  if (mm) {
    const n = BigInt('0x' + mm[1]); const bits = n.toString(2).length;
    if (bits <= 4096) { T.rsa4096.leaves.push(rsaLeaf(n, 35)); T.rsa4096.spki.push(id); }
    else if (bits <= 6144) { T.rsa6144.leaves.push(rsaLeaf(n, 52)); T.rsa6144.spki.push(id); }
    else skipped++;
    continue;
  }

  // EC: bucket by EXACT curve (a 384-bit brainpool CSCA is NOT verifiable by the
  // secp384r1 circuit, so it must not land in the p384 tree).
  let pt = null, bucket = null;
  try {
    pt = ecPoint(spkiDer);
    bucket = ecBucket(execSync('openssl x509 -noout -text', { input: b }).toString());
  } catch { pt = null; }
  if (pt && bucket && T[bucket]) { T[bucket].leaves.push(ecLeaf(pt.x, pt.y)); T[bucket].spki.push(id); }
  else { skipped++; if (pt) uncovered[bucket] = (uncovered[bucket] || 0) + 1; }
}

function buildTree(name, leaves, spki) {
  const N = 1 << DEPTH;
  const L = [...leaves], S = [...spki];
  while (L.length < N) { L.push(0n); S.push(null); }
  const layers = [L];
  while (layers[layers.length - 1].length > 1) {
    const cur = layers[layers.length - 1], nx = [];
    for (let i = 0; i < cur.length; i += 2) nx.push(pos([cur[i], cur[i + 1]]));
    layers.push(nx);
  }
  const root = layers[layers.length - 1][0];
  const paths = {};
  for (let idx = 0; idx < N; idx++) {
    if (!S[idx]) continue;
    const path = []; let i = idx;
    for (let d = 0; d < DEPTH; d++) { path.push('0x' + layers[d][i ^ 1].toString(16)); i >>= 1; }
    paths[S[idx]] = { dirs: idx, path };
  }
  const out = { root: '0x' + root.toString(16), depth: DEPTH, count: Object.keys(paths).length, paths };
  writeFileSync(`./cscatree_${name}.json`, JSON.stringify(out));
  console.log(`  ${name.padEnd(13)} ${String(out.count).padStart(4)} CSCAs  root ${out.root}`);
  return out.root;
}

const roots = {};
for (const [name, b] of Object.entries(T)) roots[`csca_root_${name}`] = buildTree(name, b.leaves, b.spki);
writeFileSync('./csca_roots.json', JSON.stringify(roots, null, 2));
console.log('skipped (no circuit):', skipped, '| uncovered EC curves:', JSON.stringify(uncovered));
process.exit(0);
