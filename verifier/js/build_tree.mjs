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
// leaf = Poseidon2 over (x||y) split into big-endian 16-byte chunks (matches the ECDSA enroll circuits)
const ecLeaf = (x, y) => { const src = Buffer.concat([x, y]); const chunks = []; for (let o = 0; o < src.length; o += 16) chunks.push(beInt(src.subarray(o, o + 16))); return pos(chunks); };

const T = { rsa4096: { leaves: [], spki: [] }, rsa6144: { leaves: [], spki: [] },
            brainpool256: { leaves: [], spki: [] }, p384: { leaves: [], spki: [] } };

// Field primes for the curves in the master list (openssl only prints an
// "ASN1 OID:" for named curves; many CSCAs inline explicit params). Mapped for
// accurate classification even when unnamed; only two are circuit-covered.
const PRIME = {
  a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377: 'brainpoolP256r1',
  '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53': 'brainpoolP384r1',
  ffffffff00000001000000000000000000000000ffffffffffffffffffffffff: 'secp256r1',
  fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff: 'secp384r1',
};
const NAMED = { prime256v1: 'secp256r1', secp256r1: 'secp256r1', secp384r1: 'secp384r1', prime384v1: 'secp384r1' };
// Identify the exact curve so each tree holds only CSCAs its circuit can verify.
function ecCurve(txt) {
  const oid = (txt.match(/ASN1 OID: (\S+)/) || [])[1];
  if (oid) return NAMED[oid] || oid;                     // named (e.g. secp384r1)
  const pm = txt.match(/Prime:\n((?:\s+[0-9a-f:]+\n)+)/); // openssl prints lowercase hex lines
  if (!pm) return null;
  let h = pm[1].replace(/[\s:]/g, '');
  if (h.startsWith('00')) h = h.slice(2);                // strip DER sign byte
  return PRIME[h] || 'ec-' + (h.length * 4) + 'bit';
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
  let pt = null, curve = null;
  try {
    pt = ecPoint(spkiDer);
    curve = ecCurve(execSync('openssl x509 -noout -text', { input: b }).toString());
  } catch { pt = null; }
  if (pt && curve === 'brainpoolP256r1' && pt.x.length === 32) { T.brainpool256.leaves.push(ecLeaf(pt.x, pt.y)); T.brainpool256.spki.push(id); }
  else if (pt && curve === 'secp384r1' && pt.x.length === 48) { T.p384.leaves.push(ecLeaf(pt.x, pt.y)); T.p384.spki.push(id); }
  else { skipped++; if (pt) uncovered[curve] = (uncovered[curve] || 0) + 1; }
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
