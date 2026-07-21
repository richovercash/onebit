// Enrollment circuit, ECDSA CSCA variant (brainpoolP256r1) -- 160 of the 588
// bundled CSCAs are brainpoolP256r1 (German/EU standard). Same shape as the RSA
// enroll circuit (ADR-005): CSCA(in master-list tree) signs the DSC, commit the
// DSC pubkey. Pairs with the RSA-2048 presentation circuit (RSA DSC).

use bignum::bignum::BigNum;
use bignum::fields::brainpoolP256r1Fq::BrainpoolP256r1_Fq;
use bignum::fields::brainpoolP256r1Fr::BrainpoolP256r1_Fr;
use ecdsa::ecdsa::verify_brainpoolp256r1_ecdsa;
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
) -> pub (Field, Field) {      // (dsc_commit, computed master-list root)
    // 1. CSCA (brainpoolP256r1) signed the DSC certificate
    let h = sha256_var(dsc_tbs, dsc_tbs_len);
    let px: BrainpoolP256r1_Fq = BrainpoolP256r1_Fq::from_be_bytes(csca_pubkey_x);
    let py: BrainpoolP256r1_Fq = BrainpoolP256r1_Fq::from_be_bytes(csca_pubkey_y);
    let r: BrainpoolP256r1_Fr = BrainpoolP256r1_Fr::from_be_bytes(csca_sig_r);
    let s: BrainpoolP256r1_Fr = BrainpoolP256r1_Fr::from_be_bytes(csca_sig_s);
    assert(verify_brainpoolp256r1_ecdsa(px, py, h, (r, s)));

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
