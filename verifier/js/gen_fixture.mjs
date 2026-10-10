// Regenerate a proof fixture after a circuit change (the vk changes with the
// circuit, so committed proofs go stale). Writes the noir-rs layout that
// scripts/split_proof.py reads: [BE u32 num_public][pub*32][proof].
//
//   python3 -c 'import json,sys,tomllib;print(json.dumps(tomllib.load(open(sys.argv[1],"rb"))))' \
//     ../../circuits/mono_faithful_ecdsa/Prover.toml > /tmp/in.json
//   CIRCUIT=mono_faithful_ecdsa.json node gen_fixture.mjs /tmp/in.json testdata/mfe_proof.bin
//
// Needs the bn254 CRS (CRS_PATH or ~/.bb-crs; fetched from the Aztec CDN if absent).
import { Barretenberg, UltraHonkBackend, BackendType } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const here = dirname(fileURLToPath(import.meta.url));
const circuit = JSON.parse(readFileSync(join(here, process.env.CIRCUIT || 'mono_faithful.json'), 'utf8'));
const [inputsPath, outPath] = process.argv.slice(2);
const { witness } = await new Noir(circuit).execute(JSON.parse(readFileSync(inputsPath, 'utf8')));

const api = await Barretenberg.new({ backend: BackendType.WasmWorker, threads: 4 });
const backend = new UltraHonkBackend(circuit.bytecode, api);
const { proof, publicInputs } = await backend.generateProof(witness);
if (!(await backend.verifyProof({ proof, publicInputs }))) throw new Error('fresh proof does not verify');

const head = Buffer.alloc(4);
head.writeUInt32BE(publicInputs.length);
const pubs = publicInputs.map(h => Buffer.from(h.replace(/^0x/, '').padStart(64, '0'), 'hex'));
writeFileSync(outPath, Buffer.concat([head, ...pubs, Buffer.from(proof)]));
console.log(`wrote ${outPath}: ${publicInputs.length} public inputs, ${proof.length}B proof`);
process.exit(0);
