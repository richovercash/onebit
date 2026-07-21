// Enrollment circuit (ADR-005): the expensive CSCA->DSC trust check, run ONCE
// at enrollment (10-50s acceptable), not per presentation. Proves a CSCA in the
// published master list signed the DSC, and commits the DSC public key so the
// fast presentation circuit (mono_faithful, DSC->SOD) can reference it.
//
// CSCA majority is RSA-4096 (357/588 in the bundled master list); this is the
// RSA-4096 variant. RSA-3072/6144 and ECDSA CSCAs are sibling variants.

use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon2::Poseidon2;
use rsa::rsa::verify_sha256_pkcs1v15;
use sha256::sha256_var;

fn main(
    dsc_tbs: [u8; 2048],       // DSC certificate TBS (what the CSCA signed; real ~1.2KB)
    dsc_tbs_len: u32,
    csca_sig: [u128; 35],      // CSCA signature over SHA256(dsc_tbs), RSA-4096
    csca_modulus: [u128; 35],
    csca_redc: [u128; 35],
    merkle_path: [Field; 10],  // path of the CSCA leaf to the master-list root (2^10)
    merkle_dirs: u32,
    dsc_modulus: [u128; 18],   // the DSC's own RSA-2048 key, to commit
    dsc_modulus_off: u32,      // where the 256-byte DSC modulus sits in dsc_tbs
) -> pub (Field, Field) {      // (dsc_commit, computed master-list root)
    // 1. CSCA signed the DSC certificate (CSCA->DSC link)
    let h = sha256_var(dsc_tbs, dsc_tbs_len);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, csca_modulus, csca_redc);
    let sig: RuntimeBigNum<35, 4096> = RuntimeBigNum { params, limbs: csca_sig };
    assert(verify_sha256_pkcs1v15(h, sig, 65537));

    // 1b. Bind dsc_modulus to the DSC public key INSIDE the signed cert, else a
    //     real CSCA->DSC_A chain could commit an attacker's unrelated DSC_B.
    //     Reconstruct the 18 little-endian 120-bit limbs from the 256 big-endian
    //     modulus bytes at dsc_modulus_off and assert equality.
    let mo = dsc_modulus_off;
    for lb in 0..17 {
        let mut v: Field = 0;
        for b in 0..15 {
            v = v * 256 + dsc_tbs[mo + 241 - 15 * lb + b] as Field;
        }
        assert(v == dsc_modulus[lb] as Field);
    }
    assert(dsc_tbs[mo] as Field == dsc_modulus[17] as Field);

    // 2. CSCA is in the master-list Merkle tree (leaf = Poseidon(CSCA modulus))
    let mut csca_fields: [Field; 35] = [0; 35];
    for i in 0..35 {
        csca_fields[i] = csca_modulus[i] as Field;
    }
    let mut node = Poseidon2::hash(csca_fields, 35);
    for i in 0..10 {
        let dir = (merkle_dirs >> i) & 1;
        let l = if dir == 1 { merkle_path[i] } else { node };
        let r = if dir == 1 { node } else { merkle_path[i] };
        node = Poseidon2::hash([l, r], 2);
    }

    // 3. Commit the DSC public key. mono_faithful commits the same value, so
    //    the two proofs chain: CSCA->DSC (here) + DSC->SOD (presentation).
    let mut dsc_fields: [Field; 18] = [0; 18];
    for i in 0..18 {
        dsc_fields[i] = dsc_modulus[i] as Field;
    }
    let dsc_commit = Poseidon2::hash(dsc_fields, 18);
    (dsc_commit, node)
}
