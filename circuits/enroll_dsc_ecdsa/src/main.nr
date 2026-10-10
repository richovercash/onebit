// SPDX-License-Identifier: Apache-2.0
// Enrollment circuit, ECDSA-DSC variant. Completes the faithful ECDSA chain:
// a CSCA (RSA-4096 here) signs a DSC whose key is ECDSA (secp256r1 / P-256), and
// we commit that DSC pubkey so mono_faithful_ecdsa (DSC->SOD) can reference it.
// The only difference from `enroll` is the DSC key type: an EC point (x,y)
// instead of an RSA modulus, so the commit + F1 binding change accordingly.

use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon2::Poseidon2;
use rsa::rsa::verify_sha256_pkcs1v15;
use sha256::sha256_var;

fn main(
    dsc_tbs: [u8; 2048],
    dsc_tbs_len: u32,
    csca_sig: [u128; 35],       // RSA-4096 CSCA signature over SHA256(dsc_tbs)
    csca_modulus: [u128; 35],
    csca_redc: [u128; 35],
    merkle_path: [Field; 10],
    merkle_dirs: u32,
    dsc_pubkey_x: [u8; 32],     // P-256 DSC public key, to commit
    dsc_pubkey_y: [u8; 32],
    dsc_pubkey_off: u32,        // offset of the 64-byte (x||y) point in dsc_tbs
) -> pub (Field, Field) {       // (dsc_commit, computed master-list root)
    // 1. CSCA (RSA-4096) signed the DSC certificate.
    let h = sha256_var(dsc_tbs, dsc_tbs_len);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, csca_modulus, csca_redc);
    let sig: RuntimeBigNum<35, 4096> = RuntimeBigNum { params, limbs: csca_sig };
    assert(verify_sha256_pkcs1v15(h, sig, 65537));

    // 1b. Bind the committed DSC pubkey (x,y) to the EC point inside the signed
    //     cert (else a real CSCA->DSC_A chain could commit an attacker's DSC_B).
    //     The uncompressed point sits contiguously (x||y) in the SPKI BIT STRING;
    //     direct byte comparison suffices (no limb reconstruction like RSA).
    let po = dsc_pubkey_off;
    // The 64-byte point must sit inside the CSCA-signed (hashed) TBS prefix;
    // bytes past dsc_tbs_len are unhashed free witness.
    assert(dsc_tbs_len <= 2048);
    assert(po + 64 <= dsc_tbs_len);
    for i in 0..32 { assert(dsc_tbs[po + i] == dsc_pubkey_x[i]); }
    for i in 0..32 { assert(dsc_tbs[po + 32 + i] == dsc_pubkey_y[i]); }

    // 2. CSCA in the master-list Merkle tree.
    let mut csca_fields: [Field; 35] = [0; 35];
    for i in 0..35 { csca_fields[i] = csca_modulus[i] as Field; }
    let mut node = Poseidon2::hash(csca_fields, 35);
    for i in 0..10 {
        let dir = (merkle_dirs >> i) & 1;
        let l = if dir == 1 { merkle_path[i] } else { node };
        let r = if dir == 1 { node } else { merkle_path[i] };
        node = Poseidon2::hash([l, r], 2);
    }

    // 3. Commit the DSC pubkey (x,y) EXACTLY as mono_faithful_ecdsa does, so the
    //    two proofs chain: CSCA->DSC (here) + DSC->SOD (presentation).
    let mut dsc_in: [Field; 4] = [0; 4];
    for i in 0..16 { dsc_in[0] = dsc_in[0] * 256 + dsc_pubkey_x[i] as Field; }
    for i in 16..32 { dsc_in[1] = dsc_in[1] * 256 + dsc_pubkey_x[i] as Field; }
    for i in 0..16 { dsc_in[2] = dsc_in[2] * 256 + dsc_pubkey_y[i] as Field; }
    for i in 16..32 { dsc_in[3] = dsc_in[3] * 256 + dsc_pubkey_y[i] as Field; }
    let dsc_commit = Poseidon2::hash(dsc_in, 4);
    (dsc_commit, node)
}