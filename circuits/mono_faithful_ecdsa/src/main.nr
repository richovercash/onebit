// Faithful presentation circuit, ECDSA-DSC variant. Same real ICAO CMS passive
// auth as mono_faithful (DG1 hash in eContent, eContent hash in signedAttrs),
// but the DSC signs the SOD with ECDSA (secp256r1 + SHA-256) instead of
// RSA. Pairs with an ECDSA-DSC enroll variant via the same dsc_commit
// (Poseidon2 over the DSC pubkey x,y). DSCs of this type appear in EU documents.

use bignum::bignum::BigNum;
use bignum::fields::secp256r1Fq::Secp256r1_Fq;
use bignum::fields::secp256r1Fr::Secp256r1_Fr;
use ecdsa::ecdsa::verify_secp256r1_ecdsa;
use poseidon::poseidon2::Poseidon2;
use sha256::{digest, sha256_var};

global MRZ_OFF: u32 = 5;

fn main(
    dg1: [u8; 93],
    econtent: [u8; 256],
    econtent_len: u32,
    signed_attrs: [u8; 128],
    signed_attrs_len: u32,
    dg1_hash_off: u32,
    econtent_hash_off: u32,
    dsc_pubkey_x: [u8; 32],    // secp256r1 (NIST P-256) DSC public key
    dsc_pubkey_y: [u8; 32],
    dsc_sig_r: [u8; 32],       // DSC signature over SHA256(signedAttrs)
    dsc_sig_s: [u8; 32],
    k: Field,
    ctx: pub Field,
    current: pub u32,
    age_min: pub u32,
) -> pub (Field, Field) { // (N, dsc_commit)
    // 1. SHA256(DG1) in the LDS security object
    let h_dg1 = digest(dg1);
    for i in 0..32 {
        assert(econtent[dg1_hash_off + i] == h_dg1[i]);
    }

    // 2. SHA256(eContent) in signedAttrs (the messageDigest attribute)
    let h_econ = sha256_var(econtent, econtent_len);
    for i in 0..32 {
        assert(signed_attrs[econtent_hash_off + i] == h_econ[i]);
    }

    // 3. ECDSA(secp256r1) DSC verifies over SHA256(signedAttrs) -- the real
    //    signed message. secp256r1 (NIST P-256) DSCs sign with SHA-256 (32-byte digest).
    let h_sa = sha256_var(signed_attrs, signed_attrs_len);
    let px: Secp256r1_Fq = Secp256r1_Fq::from_be_bytes(dsc_pubkey_x);
    let py: Secp256r1_Fq = Secp256r1_Fq::from_be_bytes(dsc_pubkey_y);
    let r: Secp256r1_Fr = Secp256r1_Fr::from_be_bytes(dsc_sig_r);
    let s: Secp256r1_Fr = Secp256r1_Fr::from_be_bytes(dsc_sig_s);
    assert(verify_secp256r1_ecdsa(px, py, h_sa, (r, s)));

    // 4. Commit the DSC public key (x,y packed into 16-byte halves). The ECDSA
    //    enroll variant commits the same value, chaining CSCA->DSC + DSC->SOD.
    let mut dsc_in: [Field; 4] = [0; 4];
    for i in 0..16 { dsc_in[0] = dsc_in[0] * 256 + dsc_pubkey_x[i] as Field; }
    for i in 16..32 { dsc_in[1] = dsc_in[1] * 256 + dsc_pubkey_x[i] as Field; }
    for i in 0..16 { dsc_in[2] = dsc_in[2] * 256 + dsc_pubkey_y[i] as Field; }
    for i in 16..32 { dsc_in[3] = dsc_in[3] * 256 + dsc_pubkey_y[i] as Field; }
    let dsc_commit = Poseidon2::hash(dsc_in, 4);

    // 5. Predicates (century rule per SPEC S3.1) + nullifier
    let dob = full_date(dg1, MRZ_OFF + 57, current);
    let exp = full_date(dg1, MRZ_OFF + 65, current);
    assert(dob + age_min * 10000 <= current);
    assert(exp >= current);
    let n = Poseidon2::hash([k, ctx], 2);
    (n, dsc_commit)
}

fn full_date(b: [u8; 93], off: u32, current: u32) -> u32 {
    let yy = (b[off] - 48) as u32 * 10 + (b[off + 1] - 48) as u32;
    let mm = (b[off + 2] - 48) as u32 * 10 + (b[off + 3] - 48) as u32;
    let dd = (b[off + 4] - 48) as u32 * 10 + (b[off + 5] - 48) as u32;
    let cur_yy = (current / 10000) % 100;
    let century = if yy > cur_yy + 10 { 1900 } else { 2000 };
    (century + yy) * 10000 + mm * 100 + dd
}
