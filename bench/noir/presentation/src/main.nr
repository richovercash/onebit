// Option B Circuit-P analog (SPEC S4.2), WITHOUT the in-circuit pi_E
// verification (that cost is measured separately from zkpassport's `outer`
// recursion circuit gate count). Opens C, proves predicates + nullifier.

use poseidon::poseidon2::Poseidon2;

fn main(
    dob: u32, // YYYYMMDD, committed attribute
    expiry: u32,
    doc_hash: Field,
    k: Field,
    salt: Field,
    ctx: pub Field, // H(verifier_id || epoch) mod p -- verifier recomputes (core Nullifier.ctx)
    current: pub u32,
    age_min: pub u32,
) -> pub (Field, Field) {
    let c = Poseidon2::hash([dob as Field, expiry as Field, doc_hash, k, salt], 5);
    assert(dob + age_min * 10000 <= current);
    assert(expiry >= current);
    let n = Poseidon2::hash([k, ctx], 2);
    (c, n) // c is bench output only; never transmitted in the real protocol
}
