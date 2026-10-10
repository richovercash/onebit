// SPDX-License-Identifier: Apache-2.0
// Faithful presentation circuit, RSA-PSS DSC variant. Identical to mono_faithful
// (real ICAO CMS passive auth: DG1 hash in eContent, eContent hash in
// signedAttrs) except the DSC signs signedAttrs with RSA-PSS (RSASSA-PSS,
// MGF1-SHA256, 32-byte salt) instead of PKCS#1 v1.5. Some EU issuers use PSS
// DSCs. dsc_commit is Poseidon2 over the RSA modulus, same as mono_faithful, so
// it pairs with the existing RSA enroll variants.

use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon2::Poseidon2;
use rsa::rsa::verify_sha256_pss;
use sha256::{digest, sha256_var};

global MRZ_OFF: u32 = 5;
global SALT_LEN: u32 = 32; // RSASSA-PSS salt length (== hash length, the common DSC choice)

fn main(
    dg1: [u8; 93],
    econtent: [u8; 256],
    econtent_len: u32,
    signed_attrs: [u8; 128],
    signed_attrs_len: u32,
    dg1_hash_off: u32,
    econtent_hash_off: u32,
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

    // 3. RSA-PSS verifies over SHA256(signedAttrs) -- the real signed message.
    let h_sa = sha256_var(signed_attrs, signed_attrs_len);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus, redc);
    let sig_bn: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: sig };
    assert(verify_sha256_pss(h_sa, sig_bn, 65537, SALT_LEN));

    // 4. Commit the DSC public key (RSA modulus), same as mono_faithful.
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