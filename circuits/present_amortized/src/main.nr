// Amortized presentation circuit (P1.0 follow-up). This is Circuit P v1's tail
// -- the rebind + predicate + nullifier -- with the ~775k-gate in-circuit
// verification of pi_E REMOVED. The document's provenance is established ONCE at
// enrollment (passive auth by the attested wallet, then C = commit(attributes)
// sealed in the SE); presentations no longer re-prove it, so they drop from
// ~20s (recursion) / ~2.5s (mono_faithful re-does passive auth) to sub-second.
//
// Trust model: Tier A (SPEC 7.3). The verifier trusts hardware attestation
// (T3) that an unmodified wallet did enrollment honestly. The ZK proof here
// still discloses exactly one bit + a nullifier -- attestation vouches for
// *document validity*, the proof vouches for *the predicate over the committed
// attributes*. Tier B (document validity proven in ZK, no attestation trust)
// still needs the per-verifier-epoch recursion; see docs/amortized-enrollment.md.
//
// F2 (self-review): the rebind ties the nullifier key k to the enrolled
// commitment C, so a given credential yields exactly one k -> one N per
// (verifier, epoch). A wallet cannot present with a k that doesn't open its
// sealed C. Combined with the SE-sealed single C per credential + attestation,
// this closes the nullifier-farming path for Tier A.

use poseidon::poseidon2::Poseidon2;

fn main(
    // --- sealed at enrollment (private), read from the SE each presentation ---
    dob: u32,          // YYYYMMDD, century rule already resolved at enrollment
    expiry: u32,       // YYYYMMDD
    doc_hash: Field,   // Poseidon2 over the document's eContent hash
    k: Field,          // nullifier PRF key (random, SE-sealed)
    salt: Field,       // commitment blinding
    c: Field,          // the enrolled commitment (sealed); rebind pins k to it
    // --- per-challenge (public) ---
    ctx: pub Field,    // H(verifier_id || epoch) mod p
    current: pub u32,  // YYYYMMDD, verifier checks == today
    age_min: pub u32,  // from the challenge policy
) -> pub Field {       // N (nullifier)
    // Rebind: the attributes we run the predicate over must open the enrolled
    // commitment. Same C construction as Circuit E / Circuit P v1.
    assert(c == Poseidon2::hash([dob as Field, expiry as Field, doc_hash, k, salt], 5));

    assert(dob + age_min * 10000 <= current); // age >= age_min (SPEC 3.1)
    assert(expiry >= current);                // document not expired

    // Verifier-scoped, epoch-scoped nullifier -- the only identifier that leaves.
    Poseidon2::hash([k, ctx], 2)
}
