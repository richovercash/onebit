// JNI bridge: native UltraHonk proving for the wallet app. Called from
// onebit.wallet.NativeProver. Runs barretenberg natively (no WebView, no
// SharedArrayBuffer, no socket) — respects V1.

use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jboolean};
use jni::JNIEnv;

use noir::barretenberg::prove::prove_ultra_honk;
use noir::barretenberg::srs::setup_srs_from_bytecode;
use noir::barretenberg::verify::get_ultra_honk_verification_key;
use noir::witness::from_vec_str_to_witness_map;

/// prove(circuitJson, witnessNewlineSeparated, g1Path, lowMem)
///   -> proof bytes ([public_inputs][proof]), or empty array on error.
#[no_mangle]
pub extern "system" fn Java_onebit_wallet_NativeProver_prove<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    circuit_json: JString<'a>,
    witness_txt: JString<'a>,
    g1_path: JString<'a>,
    low_mem: jboolean,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        let circuit_json: String = env.get_string(&circuit_json).map_err(|e| e.to_string())?.into();
        let witness_txt: String = env.get_string(&witness_txt).map_err(|e| e.to_string())?.into();
        let g1_path: String = env.get_string(&g1_path).map_err(|e| e.to_string())?.into();

        let circuit: serde_json::Value =
            serde_json::from_str(&circuit_json).map_err(|e| e.to_string())?;
        let bytecode = circuit["bytecode"].as_str().ok_or("no bytecode")?.to_string();

        let witness_vals: Vec<&str> = witness_txt
            .lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

        setup_srs_from_bytecode(&bytecode, Some(&g1_path), false)?;
        let vk = get_ultra_honk_verification_key(&bytecode, false)?;
        let iw = from_vec_str_to_witness_map(witness_vals)?;
        prove_ultra_honk(&bytecode, iw, vk, low_mem != 0)
    })();

    match result {
        Ok(proof) => env.byte_array_from_slice(&proof).unwrap_or_default().into_raw(),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", format!("native prove: {e}"));
            std::ptr::null_mut()
        }
    }
}
