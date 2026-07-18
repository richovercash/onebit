// UltraHonk verify sidecar: stdin JSON {proof: b64, publicInputs: [hex]} -> exit 0/1
import { Barretenberg, UltraHonkBackend, BackendType } from '@aztec/bb.js';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const here = dirname(fileURLToPath(import.meta.url));
const circuit = JSON.parse(readFileSync(join(here, 'circuit_p.json'), 'utf8'));
const input = JSON.parse(readFileSync(0, 'utf8'));

const api = await Barretenberg.new({ backend: BackendType.WasmWorker, threads: 4 });
const backend = new UltraHonkBackend(circuit.bytecode, api);
const ok = await backend.verifyProof({
  proof: Uint8Array.from(Buffer.from(input.proof, 'base64')),
  publicInputs: input.publicInputs,
});
console.log(ok ? 'ZK_OK' : 'ZK_FAIL');
process.exit(ok ? 0 : 1);
