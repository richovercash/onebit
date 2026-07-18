// Circuit P v0 (T5 pass 2): predicates + nullifier, proven on-device.
// ponytail: no pi_E recursion yet -- attribute binding to the enrolled
// document lands with the Circuit E fork; envelope labels this.
// C is NOT an output: commitments never leave the device (ADR-001, V2).

use poseidon::poseidon2::Poseidon2;

fn main(
    dob: u32,    // YYYYMMDD from the enrolled credential
    expiry: u32, // YYYYMMDD
    k: Field,    // nullifier PRF key, sealed at enrollment
    ctx: pub Field,   // H(verifier_id || epoch) mod p, recomputed by verifier
    current: pub u32, // YYYYMMDD; verifier checks == today
    age_min: pub u32, // from challenge policy
) -> pub Field {
    assert(dob + age_min * 10000 <= current); // age >= age_min
    assert(expiry >= current); // document not expired
    Poseidon2::hash([k, ctx], 2) // N
}
