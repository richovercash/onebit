// UltraHonk verify sidecar for mono_slim: stdin {proof: b64, publicInputs: [hex]}
// -> exit 0/1. proof is the honk proof WITHOUT public inputs (they're passed
// separately), matching noir-rs's [public_inputs][proof] split.
import { Barretenberg, UltraHonkBackend, BackendType } from '@aztec/bb.js';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const here = dirname(fileURLToPath(import.meta.url));
const circuit = JSON.parse(readFileSync(join(here, 'mono_faithful.json'), 'utf8'));
const input = JSON.parse(readFileSync(0, 'utf8'));

const api = await Barretenberg.new({ backend: BackendType.WasmWorker, threads: 4 });
const backend = new UltraHonkBackend(circuit.bytecode, api);
const ok = await backend.verifyProof({
  proof: Uint8Array.from(Buffer.from(input.proof, 'base64')),
  publicInputs: input.publicInputs,
});
console.log(ok ? 'ZK_OK' : 'ZK_FAIL');
process.exit(ok ? 0 : 1);
