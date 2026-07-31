// SPDX-License-Identifier: Apache-2.0
// Amortized presentation for a BOOLEAN age credential (mDL path). Unlike
// present_amortized, the sealed attributes are not (dob, expiry) but the
// disclosed age boolean and the threshold it attests -- because the mDL flow
// requests ONLY age_over_<n> (never birth_date/expiry, per the privacy rule),
// so the wallet never possesses a dob to commit. The commitment C reuses the
// commit_fields layout: C = Poseidon2([over, threshold, doc_hash, k, salt]),
// with `over` and `threshold` occupying the two u32 slots.
//
// ABI is byte-identical to present_amortized (6 sealed fields + ctx/current/
// age_min public -> N) so Present.java reuses the same witness builder and
// nullifier index; only the circuit asset differs.
//
// Soundness: threshold == age_min binds the credential to exactly the threshold
// the verifier asked for, so an age_over_18 credential cannot answer a 21 check.
// Document validity is established at enrollment (the wallet only presents a
// valid, non-expired mdoc + passive auth), so `current` is accepted but not
// re-checked here -- there is no expiry attribute to compare against.
use poseidon::poseidon2::Poseidon2;

fn main(
    over: u32,         // sealed: 1 iff age_over_threshold was issuer-verified true
    threshold: u32,    // sealed: the age threshold this credential attests (e.g. 18)
    doc_hash: Field,   // sealed: Poseidon/SHA over the mdoc MSO
    k: Field,          // sealed: nullifier PRF key
    salt: Field,       // sealed: commitment blinding
    c: Field,          // sealed: the enrolled commitment
    ctx: pub Field,    // H(verifier_id || epoch)
    current: pub u32,  // YYYYMMDD (verifier checks == today; not re-checked here)
    age_min: pub u32,  // challenge threshold
) -> pub Field {
    assert(c == Poseidon2::hash([over as Field, threshold as Field, doc_hash, k, salt], 5));
    assert(over == 1);              // the disclosed bit is true
    assert(threshold == age_min);   // credential attests exactly the requested threshold
    let _ = current;                // accepted in the ABI, no expiry attribute to compare
    Poseidon2::hash([k, ctx], 2)
}