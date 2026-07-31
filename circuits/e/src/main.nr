// SPDX-License-Identifier: Apache-2.0
// Circuit E v0 (P1.0): enrollment proof. Proves the document is validly
// signed by a DSC that chains to R_icao, AND that commitment C opens to the
// document's attributes. Output: C (public here; a PRIVATE input to Circuit P,
// which verifies this proof in-circuit so C never leaves the device -- ADR-001).
//
// Scope now: RSA-2048 PKCS#1v1.5 DSC (the majority alg). PSS + ECDSA + 4096
// are added as P1.1 coverage-matrix rows (separate compiled variants, same
// shape). Century rule resolved at enrollment (SPEC S3.1) using enroll_date;
// the resolved absolute YYYYMMDD is what C commits, so Circuit P compares
// absolute values with no re-resolution.
// ponytail: century resolution is enrollment-date-relative; a borderline YY
// could resolve differently across years. Stable within the +-10y window for
// realistic ages; flagged for P1.3 self-review.

use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon2::Poseidon2;
use rsa::rsa::verify_sha256_pkcs1v15;

global H_OFF: u32 = 100; // SHA256(DG1) offset inside eContent
global MRZ_OFF: u32 = 5;  // DG1 header: 61 L 5F1F L, then 88-byte TD3 MRZ

fn main(
    dg1: [u8; 93],
    econtent: [u8; 1200],
    dsc_cert: [u8; 1000],
    sig: [u128; 18],
    modulus: [u128; 18],
    redc: [u128; 18],
    merkle_path: [Field; 20],
    merkle_dirs: u32,
    k: Field,          // nullifier PRF key, sealed at enrollment
    salt: Field,       // commitment blinding
    enroll_date: u32,  // YYYYMMDD, for the century rule
) -> pub (Field, Field) { // (C, computed R_icao root) -- Circuit P asserts the
                          // root equals the pinned published value.
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

    // 3. MerkleMember(DSC, R_icao)
    let h_dsc = sha256::digest(dsc_cert);
    let mut leaf: Field = 0;
    for i in 0..31 {
        leaf = leaf * 256 + (h_dsc[i] as Field);
    }
    let mut node = leaf;
    for i in 0..20 {
        let dir = (merkle_dirs >> i) & 1;
        let l = if dir == 1 { merkle_path[i] } else { node };
        let r = if dir == 1 { node } else { merkle_path[i] };
        node = Poseidon2::hash([l, r], 2);
    }

    // 4. Commit attributes. docHash binds this credential to the concrete
    // document (its eContent), so two documents never share a commitment.
    let dob = full_date(dg1, MRZ_OFF + 57, enroll_date);
    let exp = full_date(dg1, MRZ_OFF + 65, enroll_date);
    let mut econ_acc: Field = 0;
    for i in 0..32 {
        econ_acc = econ_acc * 256 + (h_econ[i] as Field);
    }
    let doc_hash = Poseidon2::hash([econ_acc], 1);
    let c = Poseidon2::hash([dob as Field, exp as Field, doc_hash, k, salt], 5);
    (c, node)
}

// YYMMDD ascii -> YYYYMMDD int, century rule per SPEC S3.1 (identical to
// core/Mrz.java and circuit_p; divergence = soundness bug).
fn full_date(b: [u8; 93], off: u32, current: u32) -> u32 {
    let yy = (b[off] - 48) as u32 * 10 + (b[off + 1] - 48) as u32;
    let mm = (b[off + 2] - 48) as u32 * 10 + (b[off + 3] - 48) as u32;
    let dd = (b[off + 4] - 48) as u32 * 10 + (b[off + 5] - 48) as u32;
    let cur_yy = (current / 10000) % 100;
    let century = if yy > cur_yy + 10 { 1900 } else { 2000 };
    (century + yy) * 10000 + mm * 100 + dd
}