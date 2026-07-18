// Circuit P v1 (P1.0): presentation proof WITH in-circuit verification of the
// enrollment proof pi_E. This is the recursion that makes the credential
// binding real -- the attributes we prove predicates over are cryptographically
// tied to a validly-signed document, and C never leaves the device (ADR-001).
//
// Soundness chain:
//   1. pin E's circuit identity: Poseidon2(e_vkey) == e_vkey_hash (public);
//      the relying party checks e_vkey_hash equals the known Circuit E key.
//   2. verify pi_E for public inputs [C, root_e] -> proves a real document
//      was signed and C commits its attributes.
//   3. assert root_e == r_icao (pinned published master-list root).
//   4. rebind: C == Poseidon2(dob, expiry, docHash, k, salt) -- so the
//      predicate attributes are exactly the ones inside the verified C.
//   5. predicates + nullifier as before.

use std::verify_proof_with_type;
use poseidon::poseidon2::Poseidon2;

global PROOF_TYPE_HONK_ZK: u32 = 6;
global VKEY_SIZE: u32 = 115;
global PROOF_SIZE: u32 = 500;

fn main(
    // --- enrollment proof (private; verified in-circuit) ---
    e_vkey: [Field; VKEY_SIZE],
    e_proof: [Field; PROOF_SIZE],
    c: Field,          // Circuit E public output 0: the commitment
    root_e: Field,     // Circuit E public output 1: the computed master-list root
    // --- committed attributes (private; must reopen C) ---
    dob: u32,          // YYYYMMDD
    expiry: u32,       // YYYYMMDD
    doc_hash: Field,
    k: Field,
    salt: Field,
    // --- public ---
    e_vkey_hash: pub Field, // pinned Circuit E identity (RP checks against known)
    r_icao: pub Field,      // pinned published ICAO master-list root
    ctx: pub Field,         // H(verifier_id || epoch) mod p
    current: pub u32,       // YYYYMMDD, verifier checks == today
    age_min: pub u32,       // from challenge policy
) -> pub Field {            // N (nullifier)
    // 1. Pin which enrollment circuit produced this proof.
    assert(Poseidon2::hash(e_vkey, VKEY_SIZE) == e_vkey_hash);

    // 2. Verify pi_E in-circuit. Its public inputs are E's outputs [C, root].
    verify_proof_with_type(e_vkey, e_proof, [c, root_e], e_vkey_hash, PROOF_TYPE_HONK_ZK);

    // 3. The document chained to the published master-list root.
    assert(root_e == r_icao);

    // 4. Reopen C from the attributes we are about to prove over (rebind).
    assert(c == Poseidon2::hash([dob as Field, expiry as Field, doc_hash, k, salt], 5));

    // 5. Predicates (century rule already applied at enrollment inside C).
    assert(dob + age_min * 10000 <= current); // age >= age_min
    assert(expiry >= current);                // document not expired

    // 6. Verifier-scoped, epoch-scoped nullifier.
    Poseidon2::hash([k, ctx], 2)
}
