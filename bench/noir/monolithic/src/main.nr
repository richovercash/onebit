// Option A analog (SPEC S4.2): the monolithic PresentationStatement.
// Weight-faithful to: SHA256(DG1) in SOD AND VerifySig(DSC.pk over eContent,
// RSA-2048 PKCS#1v1.5) AND MerkleMember(DSC, R) AND date predicates AND nullifier.
// Omitted vs real: ASN.1 offset checks (cheap), PSS variant (similar cost).

use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon2::Poseidon2;
use rsa::rsa::verify_sha256_pkcs1v15;

global H_OFF: u32 = 100; // where SHA256(DG1) sits inside eContent
global MRZ_OFF: u32 = 5; // DG1 header: 61 L 5F1F L, then 88-byte TD3 MRZ

fn main(
    dg1: [u8; 93],
    econtent: [u8; 1200],
    dsc_cert: [u8; 1000],
    sig: [u128; 18],
    modulus: [u128; 18],
    redc: [u128; 18],
    merkle_path: [Field; 20],
    merkle_dirs: u32,
    k: Field,
    ctx: Field, // H(verifier_id || epoch)
    current: pub u32, // YYYYMMDD
    age_min: pub u32, // years
) -> pub (Field, Field) {
    // 1. SHA256(DG1) in SOD.hashList
    let h_dg1 = sha256::digest(dg1);
    for i in 0..32 {
        assert(econtent[H_OFF + i] == h_dg1[i]);
    }

    // 2. VerifySig(DSC.pk, SOD)
    let h_econ = sha256::digest(econtent);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus, redc);
    let sig_bn: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: sig };
    assert(verify_sha256_pkcs1v15(h_econ, sig_bn, 65537));

    // 3. MerkleMember(DSC, R_icao): hash the cert, fold a depth-20 path
    let h_dsc = sha256::digest(dsc_cert);
    let mut leaf: Field = 0;
    for i in 0..31 {
        leaf = leaf * 256 + (h_dsc[i] as Field);
    }
    let mut node = leaf;
    for i in 0..20 {
        let dir = (merkle_dirs >> (i as u32)) & 1;
        let l = if dir == 1 { merkle_path[i] } else { node };
        let r = if dir == 1 { node } else { merkle_path[i] };
        node = Poseidon2::hash([l, r], 2);
    }

    // 4. Date predicates with the S3.1 century rule
    let dob_full = full_date(dg1, MRZ_OFF + 57, current);
    let exp_full = full_date(dg1, MRZ_OFF + 65, current);
    assert(dob_full + age_min * 10000 <= current); // mrz_dob <= T - age_min
    assert(exp_full >= current); // mrz_expiry >= T

    // 5. N = Poseidon(k, H(verifier_id || epoch))
    let n = Poseidon2::hash([k, ctx], 2);
    (n, node)
}

// YYMMDD ascii at off -> YYYYMMDD int, century per SPEC S3.1
fn full_date(b: [u8; 93], off: u32, current: u32) -> u32 {
    let yy = (b[off] - 48) as u32 * 10 + (b[off + 1] - 48) as u32;
    let mm = (b[off + 2] - 48) as u32 * 10 + (b[off + 3] - 48) as u32;
    let dd = (b[off + 4] - 48) as u32 * 10 + (b[off + 5] - 48) as u32;
    let cur_yy = (current / 10000) % 100;
    let century = if yy > cur_yy + 10 { 1900 } else { 2000 };
    (century + yy) * 10000 + mm * 100 + dd
}
