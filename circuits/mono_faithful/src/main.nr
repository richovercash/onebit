// SPDX-License-Identifier: Apache-2.0
// Faithful monolithic presentation circuit -- models real ICAO CMS passive
// authentication (unlike mono_slim which signed eContent directly).
//
// Real chain (measured with core/CmsProbe on a jmrtd-built SOD):
//   SHA256(DG1)      appears in eContent  (LDS security object)
//   SHA256(eContent) appears in signedAttrs (CMS messageDigest attribute)
//   RSA_verify( SHA256(signedAttrs) )      -- signedAttrs is 0x31 SET OF tagged
// Offsets/lengths are witness inputs (the prover can't forge them: the hashes
// must genuinely sit inside the RSA-signed structures). Variable-length SHA so
// padded arrays hash only their real bytes.

use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon2::Poseidon2;
use rsa::rsa::verify_sha256_pkcs1v15;
use sha256::{digest, sha256_var};

global MRZ_OFF: u32 = 5;

fn main(
    dg1: [u8; 93],
    econtent: [u8; 256],       // LDS security object (real ~178B)
    econtent_len: u32,
    signed_attrs: [u8; 128],   // CMS signedAttributes (real ~74B)
    signed_attrs_len: u32,
    dg1_hash_off: u32,         // SHA256(DG1) offset in econtent
    econtent_hash_off: u32,    // SHA256(econtent) offset in signed_attrs
    sig: [u128; 18],
    modulus: [u128; 18],
    redc: [u128; 18],
    k: Field,
    ctx: pub Field,
    current: pub u32,
    age_min: pub u32,
) -> pub (Field, Field) { // (N, dsc_commit)
    // 0. Offsets must lie inside the HASHED prefix. sha256_var zero-substitutes
    //    bytes at index >= *_len, so the array tail is free witness: an offset
    //    into it would let the prover plant any hash past the signed bytes.
    assert(econtent_len <= 256);
    assert(signed_attrs_len <= 128);
    assert(dg1_hash_off + 32 <= econtent_len);
    assert(econtent_hash_off + 32 <= signed_attrs_len);

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

    // 3. RSA verifies over SHA256(signedAttrs) -- the real signed message
    let h_sa = sha256_var(signed_attrs, signed_attrs_len);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus, redc);
    let sig_bn: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: sig };
    assert(verify_sha256_pkcs1v15(h_sa, sig_bn, 65537));

    // 4. Commit the DSC public key. The enrollment proof commits the same
    //    Poseidon2(dsc_modulus); matching dsc_commit chains CSCA->DSC (enroll)
    //    with DSC->SOD (here). See docs/stage-enrollment-circuit.md.
    let mut mod_fields: [Field; 18] = [0; 18];
    for i in 0..18 {
        mod_fields[i] = modulus[i] as Field;
    }
    let dsc_commit = Poseidon2::hash(mod_fields, 18);

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