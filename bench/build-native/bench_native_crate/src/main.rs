// Native on-device proving benchmark for the One-Bit Verifier.
// Usage: bench_native <circuit.json> <witness.txt> <g1.dat> <runs> [low_mem]
//   circuit.json : compiled Noir circuit (uses its "bytecode" field)
//   witness.txt  : ABI-ordered input values, one decimal per line
//   g1.dat       : bn254 G1 SRS points (offline; G2 is hardcoded in noir-rs)
//   runs         : number of proof runs to time
//   low_mem      : optional "1" to enable mobile low-memory mode
//
// Prints per-run prove time and verifies the last proof. This runs as a plain
// ARM binary via `adb shell`, so it uses all cores natively — no WebView, no
// SharedArrayBuffer, no network, no INTERNET permission (respects V1).

use std::time::Instant;

use noir::barretenberg::prove::prove_ultra_honk;
use noir::barretenberg::srs::setup_srs_from_bytecode;
use noir::barretenberg::verify::{get_ultra_honk_verification_key, verify_ultra_honk};
use noir::witness::from_vec_str_to_witness_map;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: bench_native <circuit.json> <witness.txt> <g1.dat> <runs> [low_mem]");
        std::process::exit(2);
    }
    let circuit_json = std::fs::read_to_string(&args[1]).expect("read circuit");
    let circuit: serde_json::Value = serde_json::from_str(&circuit_json).expect("parse circuit");
    let bytecode = circuit["bytecode"].as_str().expect("bytecode field").to_string();

    let witness_txt = std::fs::read_to_string(&args[2]).expect("read witness");
    let witness_vals: Vec<&str> = witness_txt
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    let g1_path = args[3].clone();
    let runs: usize = args[4].parse().expect("runs");
    let low_mem = args.get(5).map(|s| s == "1").unwrap_or(false);

    println!("circuit bytecode {} b64 chars, {} witness inputs, low_mem={}",
             bytecode.len(), witness_vals.len(), low_mem);

    let t = Instant::now();
    let n_points = setup_srs_from_bytecode(&bytecode, Some(&g1_path), false)
        .expect("srs setup (g1.dat too small?)");
    println!("SRS ready: {} points in {:?}", n_points, t.elapsed());

    let t = Instant::now();
    let vk = get_ultra_honk_verification_key(&bytecode, false).expect("vk");
    println!("vk in {:?}", t.elapsed());

    let mut last_proof = Vec::new();
    for i in 0..runs {
        let iw = from_vec_str_to_witness_map(witness_vals.clone()).expect("witness map");
        let t = Instant::now();
        last_proof = prove_ultra_honk(&bytecode, iw, vk.clone(), low_mem).expect("prove");
        println!("run {}: prove {:?} (proof {} bytes)", i, t.elapsed(), last_proof.len());
    }

    let ok = verify_ultra_honk(last_proof, vk).expect("verify");
    println!("VERIFY: {}", if ok { "OK" } else { "FAIL" });
}
