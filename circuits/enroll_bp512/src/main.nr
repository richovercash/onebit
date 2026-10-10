// SPDX-License-Identifier: Apache-2.0
// Enrollment circuit, brainpoolP512r1 CSCA variant. brainpoolP512r1 CSCAs sign
// with SHA-512; coordinates/scalars are 64 bytes (512 bits). Same shape as the
// other ECDSA enroll variants. The leaf packs each 64-byte coordinate into four
// 16-byte chunks. DSC is RSA-2048.

use bignum::bignum::BigNum;
use bignum::fields::brainpoolP512r1Fq::BrainpoolP512r1_Fq;
use bignum::fields::brainpoolP512r1Fr::BrainpoolP512r1_Fr;
use ecdsa::ecdsa::verify_brainpoolp512r1_ecdsa;
use poseidon::poseidon2::Poseidon2;
use sha512::sha512;

fn main(
    dsc_tbs: [u8; 2048],
    dsc_tbs_len: u32,
    csca_pubkey_x: [u8; 64],
    csca_pubkey_y: [u8; 64],
    csca_sig_r: [u8; 64],
    csca_sig_s: [u8; 64],
    merkle_path: [Field; 10],
    merkle_dirs: u32,
    dsc_modulus: [u128; 18],   // RSA-2048 DSC key, to commit
    dsc_modulus_off: u32,
) -> pub (Field, Field) {       // (dsc_commit, computed master-list root)
    // 1. CSCA (brainpoolP512r1) signed the DSC cert; it uses SHA-512.
    let tbs_vec: BoundedVec<u8, 2048> = BoundedVec::from_parts(dsc_tbs, dsc_tbs_len);
    let h: [u8; 64] = sha512::sha512_var(tbs_vec);
    let px: BrainpoolP512r1_Fq = BrainpoolP512r1_Fq::from_be_bytes(csca_pubkey_x);
    let py: BrainpoolP512r1_Fq = BrainpoolP512r1_Fq::from_be_bytes(csca_pubkey_y);
    let r: BrainpoolP512r1_Fr = BrainpoolP512r1_Fr::from_be_bytes(csca_sig_r);
    let s: BrainpoolP512r1_Fr = BrainpoolP512r1_Fr::from_be_bytes(csca_sig_s);
    assert(verify_brainpoolp512r1_ecdsa(px, py, h, (r, s)));

    // 1b. Bind dsc_modulus (RSA-2048 DSC) to the pubkey inside the signed cert.
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
    //    (x,y), each 64 bytes packed into four 16-byte chunks.
    let mut leaf_in: [Field; 8] = [0; 8];
    for i in 0..16 { leaf_in[0] = leaf_in[0] * 256 + csca_pubkey_x[i] as Field; }
    for i in 16..32 { leaf_in[1] = leaf_in[1] * 256 + csca_pubkey_x[i] as Field; }
    for i in 32..48 { leaf_in[2] = leaf_in[2] * 256 + csca_pubkey_x[i] as Field; }
    for i in 48..64 { leaf_in[3] = leaf_in[3] * 256 + csca_pubkey_x[i] as Field; }
    for i in 0..16 { leaf_in[4] = leaf_in[4] * 256 + csca_pubkey_y[i] as Field; }
    for i in 16..32 { leaf_in[5] = leaf_in[5] * 256 + csca_pubkey_y[i] as Field; }
    for i in 32..48 { leaf_in[6] = leaf_in[6] * 256 + csca_pubkey_y[i] as Field; }
    for i in 48..64 { leaf_in[7] = leaf_in[7] * 256 + csca_pubkey_y[i] as Field; }
    let mut node = Poseidon2::hash(leaf_in, 8);
    for i in 0..10 {
        let dir = (merkle_dirs >> i) & 1;
        let l = if dir == 1 { merkle_path[i] } else { node };
        let rr = if dir == 1 { node } else { merkle_path[i] };
        node = Poseidon2::hash([l, rr], 2);
    }

    // 3. Commit the DSC public key (RSA-2048).
    let mut dsc_fields: [Field; 18] = [0; 18];
    for i in 0..18 { dsc_fields[i] = dsc_modulus[i] as Field; }
    let dsc_commit = Poseidon2::hash(dsc_fields, 18);
    (dsc_commit, node)
}