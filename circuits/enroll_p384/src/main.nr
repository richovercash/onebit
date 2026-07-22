// Enrollment circuit, P-384 (secp384r1) CSCA variant. 4 of the 588 bundled
// master-list CSCAs are P-384. Same shape as enroll_ecdsa (brainpoolP256r1):
// CSCA (in the master-list tree) signs the DSC, commit the DSC pubkey. P-384
// certs sign with SHA-384, and coordinates/scalars are 48 bytes. DSC is RSA-2048.

use bignum::bignum::BigNum;
use bignum::fields::secp384r1Fq::Secp384r1_Fq;
use bignum::fields::secp384r1Fr::Secp384r1_Fr;
use ecdsa::ecdsa::verify_secp384r1_ecdsa;
use poseidon::poseidon2::Poseidon2;
use sha512::sha384;

fn main(
    dsc_tbs: [u8; 2048],
    dsc_tbs_len: u32,
    csca_pubkey_x: [u8; 48],
    csca_pubkey_y: [u8; 48],
    csca_sig_r: [u8; 48],
    csca_sig_s: [u8; 48],
    merkle_path: [Field; 10],
    merkle_dirs: u32,
    dsc_modulus: [u128; 18],   // RSA-2048 DSC key, to commit
    dsc_modulus_off: u32,      // where the 256-byte DSC modulus sits in dsc_tbs
) -> pub (Field, Field) {      // (dsc_commit, computed master-list root)
    // 1. CSCA (secp384r1 / NIST P-384) signed the DSC cert; P-384 uses SHA-384.
    let tbs_vec: BoundedVec<u8, 2048> = BoundedVec::from_parts(dsc_tbs, dsc_tbs_len);
    let h: [u8; 48] = sha384::sha384_var(tbs_vec);
    let px: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(csca_pubkey_x);
    let py: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(csca_pubkey_y);
    let r: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(csca_sig_r);
    let s: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(csca_sig_s);
    assert(verify_secp384r1_ecdsa(px, py, h, (r, s)));

    // 1b. Bind dsc_modulus (RSA-2048 DSC) to the pubkey inside the signed cert.
    let mo = dsc_modulus_off;
    for lb in 0..17 {
        let mut v: Field = 0;
        for b in 0..15 {
            v = v * 256 + dsc_tbs[mo + 241 - 15 * lb + b] as Field;
        }
        assert(v == dsc_modulus[lb] as Field);
    }
    assert(dsc_tbs[mo] as Field == dsc_modulus[17] as Field);

    // 2. CSCA in the master-list Merkle tree. Leaf = Poseidon2 over the pubkey
    //    (x,y), each 48 bytes packed into three 16-byte thirds.
    let mut leaf_in: [Field; 6] = [0; 6];
    for i in 0..16 { leaf_in[0] = leaf_in[0] * 256 + csca_pubkey_x[i] as Field; }
    for i in 16..32 { leaf_in[1] = leaf_in[1] * 256 + csca_pubkey_x[i] as Field; }
    for i in 32..48 { leaf_in[2] = leaf_in[2] * 256 + csca_pubkey_x[i] as Field; }
    for i in 0..16 { leaf_in[3] = leaf_in[3] * 256 + csca_pubkey_y[i] as Field; }
    for i in 16..32 { leaf_in[4] = leaf_in[4] * 256 + csca_pubkey_y[i] as Field; }
    for i in 32..48 { leaf_in[5] = leaf_in[5] * 256 + csca_pubkey_y[i] as Field; }
    let mut node = Poseidon2::hash(leaf_in, 6);
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
