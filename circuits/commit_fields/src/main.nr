// SPDX-License-Identifier: Apache-2.0
// Generic credential commitment: C = Poseidon2(dob, expiry, doc_hash, k, salt).
// Used by enrollment paths where the attributes are supplied directly (mDL: dob
// and expiry come from mdoc data elements, not from an in-circuit DG1 parse).
// Byte-identical to the C that present_amortized reopens, so an mDL credential
// presents through the unchanged presentation circuit.
use poseidon::poseidon2::Poseidon2;

fn main(dob: u32, expiry: u32, doc_hash: Field, k: Field, salt: Field) -> pub Field {
    Poseidon2::hash([dob as Field, expiry as Field, doc_hash, k, salt], 5)
}