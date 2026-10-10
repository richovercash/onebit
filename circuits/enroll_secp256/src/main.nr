// SPDX-License-Identifier: Apache-2.0
// Enrollment circuit, ECDSA CSCA variant (secp256r1 (NIST P-256)) -- 160 of the 588
// bundled CSCAs are secp256r1 (NIST P-256) (German/EU standard). Same shape as the RSA
// enroll circuit (ADR-005): CSCA(in master-list tree) signs the DSC, commit the
// DSC pubkey. Pairs with the RSA-2048 presentation circuit (RSA DSC).

use bignum::bignum::BigNum;
use bignum::fields::secp256r1Fq::Secp256r1_Fq;
use bignum::fields::secp256r1Fr::Secp256r1_Fr;
use ecdsa::ecdsa::verify_secp256r1_ecdsa;
use poseidon::poseidon2::Poseidon2;
use sha256::sha256_var;

fn main(
    dsc_tbs: [u8; 2048],
    dsc_tbs_len: u32,
    csca_pubkey_x: [u8; 32],
    csca_pubkey_y: [u8; 32],
    csca_sig_r: [u8; 32],
    csca_sig_s: [u8; 32],
    merkle_path: [Field; 10],
    merkle_dirs: u32,
    dsc_modulus: [u128; 18],   // RSA-2048 DSC key, to commit
    dsc_modulus_off: u32,      // where the 256-byte DSC modulus sits in dsc_tbs
) -> pub (Field, Field) {      // (dsc_commit, computed master-list root)
    // 1. CSCA (secp256r1 (NIST P-256)) signed the DSC certificate
    let h = sha256_var(dsc_tbs, dsc_tbs_len);
    let px: Secp256r1_Fq = Secp256r1_Fq::from_be_bytes(csca_pubkey_x);
    let py: Secp256r1_Fq = Secp256r1_Fq::from_be_bytes(csca_pubkey_y);
    let r: Secp256r1_Fr = Secp256r1_Fr::from_be_bytes(csca_sig_r);
    let s: Secp256r1_Fr = Secp256r1_Fr::from_be_bytes(csca_sig_s);
    assert(verify_secp256r1_ecdsa(px, py, h, (r, s)));

    // 1b. Bind dsc_modulus to the DSC pubkey inside the signed cert (else a real
    //     CSCA->DSC_A chain could commit an attacker's DSC_B). See enroll.nr.
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

    // 2. CSCA in the master-list Merkle tree. Leaf = Poseidon2 over the pubkey
    //    (x,y) packed into 16-byte halves.
    let mut leaf_in: [Field; 4] = [0; 4];
    for i in 0..16 { leaf_in[0] = leaf_in[0] * 256 + csca_pubkey_x[i] as Field; }
    for i in 16..32 { leaf_in[1] = leaf_in[1] * 256 + csca_pubkey_x[i] as Field; }
    for i in 0..16 { leaf_in[2] = leaf_in[2] * 256 + csca_pubkey_y[i] as Field; }
    for i in 16..32 { leaf_in[3] = leaf_in[3] * 256 + csca_pubkey_y[i] as Field; }
    let mut node = Poseidon2::hash(leaf_in, 4);
    for i in 0..10 {
        let dir = (merkle_dirs >> i) & 1;
        let l = if dir == 1 { merkle_path[i] } else { node };
        let rr = if dir == 1 { node } else { merkle_path[i] };
        node = Poseidon2::hash([l, rr], 2);
    }

    // 3. Commit the DSC public key (same as the RSA enroll variant)
    let mut dsc_fields: [Field; 18] = [0; 18];
    for i in 0..18 { dsc_fields[i] = dsc_modulus[i] as Field; }
    let dsc_commit = Poseidon2::hash(dsc_fields, 18);
    (dsc_commit, node)
}