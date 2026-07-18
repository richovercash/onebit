// Enrollment commitment helper: the exact (doc_hash, C) computation Circuit E
// performs, factored out so the wallet can persist the credential fields
// (dob, expiry, doc_hash, k, salt, C) that Circuit P later reopens. Kept
// byte-identical to circuit_e's step 1 + step 4.

use poseidon::poseidon2::Poseidon2;

global H_OFF: u32 = 100;
global MRZ_OFF: u32 = 5;

fn main(
    dg1: [u8; 93],
    econtent: [u8; 1200],
    k: Field,
    salt: Field,
    enroll_date: u32,
) -> pub (Field, Field) { // (C, doc_hash)
    let h_econ = sha256::digest(econtent);
    let dob = full_date(dg1, MRZ_OFF + 57, enroll_date);
    let exp = full_date(dg1, MRZ_OFF + 65, enroll_date);
    let mut econ_acc: Field = 0;
    for i in 0..32 {
        econ_acc = econ_acc * 256 + (h_econ[i] as Field);
    }
    let doc_hash = Poseidon2::hash([econ_acc], 1);
    let c = Poseidon2::hash([dob as Field, exp as Field, doc_hash, k, salt], 5);
    (c, doc_hash)
}

fn full_date(b: [u8; 93], off: u32, current: u32) -> u32 {
    let yy = (b[off] - 48) as u32 * 10 + (b[off + 1] - 48) as u32;
    let mm = (b[off + 2] - 48) as u32 * 10 + (b[off + 3] - 48) as u32;
    let dd = (b[off + 4] - 48) as u32 * 10 + (b[off + 5] - 48) as u32;
    let cur_yy = (current / 10000) % 100;
    let century = if yy > cur_yy + 10 { 1900 } else { 2000 };
    (century + yy) * 10000 + mm * 100 + dd
}
