// SPDX-License-Identifier: Apache-2.0
// Slimmed monolithic presentation circuit (real input sizes).
// vs bench monolithic: eContent 1200->256 bytes (measured real LDS object is
// ~74B; 256 covers a passport with many data groups), and the DSC identity is
// committed with Poseidon over the 18 modulus limbs instead of SHA-256 over a
// 1000-byte cert. Net: ~37 SHA blocks -> ~6, cutting the memory-bound cost.

use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon2::Poseidon2;
use rsa::rsa::verify_sha256_pkcs1v15;

global H_OFF: u32 = 30;   // SHA256(DG1) offset inside the LDS security object
global MRZ_OFF: u32 = 5;  // DG1 header then 88-byte TD3 MRZ

fn main(
    dg1: [u8; 93],
    econtent: [u8; 256],  // LDS security object (real ~74B, padded to 256)
    sig: [u128; 18],
    modulus: [u128; 18],
    redc: [u128; 18],
    merkle_path: [Field; 20],
    merkle_dirs: u32,
    k: Field,
    ctx: pub Field,   // H(verifier_id || epoch) -- verifier recomputes + binds N
    current: pub u32,
    age_min: pub u32,
) -> pub (Field, Field) { // (N, dsc_root)
    // 1. SHA256(DG1) in the LDS security object
    let h_dg1 = sha256::digest(dg1);
    for i in 0..32 {
        assert(econtent[H_OFF + i] == h_dg1[i]);
    }

    // 2. VerifySig(DSC.pk, SOD)
    let h_econ = sha256::digest(econtent);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus, redc);
    let sig_bn: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: sig };
    assert(verify_sha256_pkcs1v15(h_econ, sig_bn, 65537));

    // 3. DSC identity = Poseidon(modulus limbs) -- no SHA over the cert.
    let mut mod_fields: [Field; 18] = [0; 18];
    for i in 0..18 {
        mod_fields[i] = modulus[i] as Field;
    }
    let mut node = Poseidon2::hash(mod_fields, 18);
    for i in 0..20 {
        let dir = (merkle_dirs >> i) & 1;
        let l = if dir == 1 { merkle_path[i] } else { node };
        let r = if dir == 1 { node } else { merkle_path[i] };
        node = Poseidon2::hash([l, r], 2);
    }

    // 4. Date predicates (century rule per SPEC S3.1)
    let dob = full_date(dg1, MRZ_OFF + 57, current);
    let exp = full_date(dg1, MRZ_OFF + 65, current);
    assert(dob + age_min * 10000 <= current);
    assert(exp >= current);

    // 5. Nullifier
    let n = Poseidon2::hash([k, ctx], 2);
    (n, node)
}

fn full_date(b: [u8; 93], off: u32, current: u32) -> u32 {
    let yy = (b[off] - 48) as u32 * 10 + (b[off + 1] - 48) as u32;
    let mm = (b[off + 2] - 48) as u32 * 10 + (b[off + 3] - 48) as u32;
    let dd = (b[off + 4] - 48) as u32 * 10 + (b[off + 5] - 48) as u32;
    let cur_yy = (current / 10000) % 100;
    let century = if yy > cur_yy + 10 { 1900 } else { 2000 };
    (century + yy) * 10000 + mm * 100 + dd
}