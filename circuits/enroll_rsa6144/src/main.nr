// SPDX-License-Identifier: Apache-2.0
// Enrollment circuit, RSA-6144 CSCA variant. 6 of the 588 bundled master-list
// CSCAs are RSA-6144. Identical shape to the RSA-4096 enroll (ADR-005): CSCA (in
// the master-list tree) signs the DSC, commit the DSC pubkey. Only the CSCA key
// size changes -> 52 limbs of 120 bits (ceil(6144/120)). DSC is still RSA-2048.

use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon2::Poseidon2;
use rsa::rsa::verify_sha256_pkcs1v15;
use sha256::sha256_var;

fn main(
    dsc_tbs: [u8; 2048],
    dsc_tbs_len: u32,
    csca_sig: [u128; 52],      // CSCA signature over SHA256(dsc_tbs), RSA-6144
    csca_modulus: [u128; 52],
    csca_redc: [u128; 52],
    merkle_path: [Field; 10],
    merkle_dirs: u32,
    dsc_modulus: [u128; 18],   // the DSC's own RSA-2048 key, to commit
    dsc_modulus_off: u32,      // where the 256-byte DSC modulus sits in dsc_tbs
) -> pub (Field, Field) {      // (dsc_commit, computed master-list root)
    // 1. CSCA (RSA-6144) signed the DSC certificate.
    let h = sha256_var(dsc_tbs, dsc_tbs_len);
    let params: BigNumParams<52, 6144> = BigNumParams::new(false, csca_modulus, csca_redc);
    let sig: RuntimeBigNum<52, 6144> = RuntimeBigNum { params, limbs: csca_sig };
    assert(verify_sha256_pkcs1v15(h, sig, 65537));

    // 1b. Bind dsc_modulus to the DSC pubkey inside the signed cert (see enroll.nr).
    let mo = dsc_modulus_off;
    // The 256-byte window must sit inside the CSCA-signed (hashed) TBS prefix;
    // bytes past dsc_tbs_len are unhashed free witness.
    assert(dsc_tbs_len <= 2048);
    assert(mo + 256 <= dsc_tbs_len);
    for lb in 0..17 {
        let mut v: Field = 0;
        for b in 0..15 {
            v = v * 256 + dsc_tbs[mo + 241 - 15 * lb + b] as Field;
        }
        assert(v == dsc_modulus[lb] as Field);
    }
    assert(dsc_tbs[mo] as Field == dsc_modulus[17] as Field);

    // 2. CSCA in the master-list Merkle tree. Leaf = Poseidon2(52 modulus limbs).
    let mut csca_fields: [Field; 52] = [0; 52];
    for i in 0..52 {
        csca_fields[i] = csca_modulus[i] as Field;
    }
    let mut node = Poseidon2::hash(csca_fields, 52);
    for i in 0..10 {
        let dir = (merkle_dirs >> i) & 1;
        let l = if dir == 1 { merkle_path[i] } else { node };
        let r = if dir == 1 { node } else { merkle_path[i] };
        node = Poseidon2::hash([l, r], 2);
    }

    // 3. Commit the DSC public key (same value mono_faithful commits).
    let mut dsc_fields: [Field; 18] = [0; 18];
    for i in 0..18 {
        dsc_fields[i] = dsc_modulus[i] as Field;
    }
    let dsc_commit = Poseidon2::hash(dsc_fields, 18);
    (dsc_commit, node)
}