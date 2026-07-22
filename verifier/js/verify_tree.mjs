// Sanity: for one real CSCA per EC tree, recompute the leaf from its certificate
// (exactly as the wallet does), fold its stored Merkle path, and confirm it
// reaches the tree's root. Proves leaf-construction + path + root are consistent
// end to end. Usage: node verify_tree.mjs <masterlist.pem>
import { BarretenbergSync } from '@aztec/bb.js';
import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import { createHash } from 'crypto';

const api = await BarretenbergSync.initSingleton();
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const frBuf = (v) => { let b = Buffer.alloc(32); let x = ((BigInt(v) % P) + P) % P; for (let i = 31; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const pos = (arr) => BigInt('0x' + Buffer.from(api.poseidon2Hash({ inputs: arr.map(frBuf) }).hash).toString('hex'));
const beInt = (buf) => { let x = 0n; for (const b of buf) x = (x << 8n) + BigInt(b); return x; };
const ecLeaf = (x, y) => { const s = Buffer.concat([x, y]); const c = []; for (let o = 0; o < s.length; o += 16) c.push(beInt(s.subarray(o, o + 16))); return pos(c); };
function tlv(b, o) { let i = o + 1, l = b[i++]; if (l & 0x80) { let n = l & 0x7f; l = 0; while (n-- > 0) l = (l << 8) | b[i++]; } return { tag: b[o], hEnd: i, end: i + l }; }
function ecPoint(s) { const seq = tlv(s, 0), alg = tlv(s, seq.hEnd), bs = tlv(s, alg.end); const p = s.subarray(bs.hEnd + 1, bs.end); const c = (p.length - 1) / 2; return { x: p.subarray(1, 1 + c), y: p.subarray(1 + c) }; }

const pem = readFileSync(process.argv[2] || './masterlist.pem', 'utf8');
const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);

let pass = 0, checked = 0;
for (const [tree, wantBits] of [['brainpool256', 256], ['p384', 384]]) {
  const t = JSON.parse(readFileSync(`./cscatree_${tree}.json`, 'utf8'));
  for (const b of blocks) {
    let spkiDer;
    try { const der = execSync('openssl x509 -noout -pubkey', { input: b }).toString(); spkiDer = Buffer.from(der.split('\n').filter(l => !l.includes('---')).join(''), 'base64'); } catch { continue; }
    const id = createHash('sha256').update(spkiDer).digest('hex');
    if (!t.paths[id]) continue;                         // not in this tree
    const pt = ecPoint(spkiDer);
    if (pt.x.length * 8 !== wantBits) continue;
    let node = ecLeaf(pt.x, pt.y);
    const { dirs, path } = t.paths[id];
    for (let d = 0; d < path.length; d++) {
      const sib = BigInt(path[d]);
      node = ((dirs >> d) & 1) ? pos([sib, node]) : pos([node, sib]);
    }
    checked++;
    const ok = ('0x' + node.toString(16)) === t.root;
    console.log(`  ${tree}: leaf ${id.slice(0, 12)}… folds to root: ${ok ? 'OK' : 'MISMATCH'}`);
    if (ok) pass++;
    break;                                              // one per tree is enough
  }
}
console.log(pass === checked && checked === 2 ? 'TREE_OK' : 'TREE_FAIL');
process.exit(pass === checked && checked === 2 ? 0 : 1);
