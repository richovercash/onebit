// SPDX-License-Identifier: AGPL-3.0-only
package onebit.wallet;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricPrompt;
import android.net.Uri;
import android.os.CancellationSignal;
import android.util.Base64;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.Certificate;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

import org.json.JSONArray;
import org.json.JSONObject;

import onebit.core.Challenge;
import onebit.core.Nullifier;

/**
 * P0 presentation with NATIVE proving (mono_slim, ~2.5s foreground). Flow:
 * refusal check -> biometric (opens the Seal auth window AND authorizes the
 * ephemeral device key) -> unseal witness -> native UltraHonk proof (real
 * RSA passive-auth + predicate + nullifier in one circuit) ->
 * device_sig over H(nonce||origin||SHA256(proof)) -> response via browser.
 *
 * Public inputs (mono_slim): [ctx, current, age_min, N, dsc_root].
 */
final class Present {

    static final String RETURN_URL = "http://localhost:8317/present?r=";
    static final int PUB_COUNT = 5;      // ctx, current, age_min, N, dsc_root
    static final String CIRCUIT = "zk/mono_faithful.json"; // real CMS passive auth

    private final Activity a;
    private final Consumer<String> say;
    private final Runnable onProving;   // fired once all refusal checks pass, before proving begins
    private boolean amortized;   // Tier A fast path: acred.bin enrolled
    private String amortCircuit = "zk/present_amortized.json"; // or present_bool for mDL boolean creds
    private String faithfulCircuit = "mono_faithful"; // or _pss / _ecdsa by DSC type

    Present(Activity a, Consumer<String> say) { this(a, say, () -> {}); }

    Present(Activity a, Consumer<String> say, Runnable onProving) {
        this.a = a;
        this.say = say;
        this.onProving = onProving;
    }

    void start(String challengeJson) {
        long t0 = System.currentTimeMillis();
        final Challenge c;
        try {
            c = Challenge.parse(challengeJson);
        } catch (Challenge.RefusalException e) {
            say.accept("REFUSED (V5): " + e.getMessage());
            return;
        }
        if (!c.verifySig()) {
            say.accept("REFUSED (V5): verifier signature invalid — challenge not authentic.");
            return;
        }
        // Assurance gate (wallet-side, upfront): a person-bound policy needs a face-matched
        // credential. Today's credentials are bearer-only, so refuse HERE — before proving or
        // collecting a fingerprint — so a rejecting site gets no proof, no nullifier, no auth.
        if (c.personBound && !new java.io.File(a.getFilesDir(), "personbound.txt").exists()) {
            say.accept("REFUSED: this site requires a face-matched (person-bound) ID.\n"
                    + "Your credential is bearer-only — nothing was sent.");
            return;
        }
        if (NativeProver.loadError != null) {
            say.accept("Native prover unavailable: " + NativeProver.loadError);
            return;
        }
        SharedPreferences cred = a.getSharedPreferences("cred", Context.MODE_PRIVATE);
        // Prefer the amortized Tier A path (~0.8s) if its credential is enrolled;
        // fall back to the faithful mono path (~2.5s, full CMS passive auth).
        amortized = new java.io.File(a.getFilesDir(), "acred.bin").exists();
        try {
            faithfulCircuit = new String(java.nio.file.Files.readAllBytes(
                    new java.io.File(a.getFilesDir(), "presalg.txt").toPath()),
                    StandardCharsets.UTF_8).trim();
        } catch (Exception e) { faithfulCircuit = "mono_faithful"; }
        // mDL credentials commit a boolean (not dob/expiry) -> present_bool, same ABI.
        try {
            if (new String(java.nio.file.Files.readAllBytes(
                    new java.io.File(a.getFilesDir(), "credtype.txt").toPath()),
                    StandardCharsets.UTF_8).trim().equals("bool"))
                amortCircuit = "zk/present_bool.json";
        } catch (Exception e) { amortCircuit = "zk/present_amortized.json"; }
        java.io.File docWit = new java.io.File(a.getFilesDir(), "docwit.txt");
        if (!amortized && (!cred.contains("k") || !docWit.exists())) {
            say.accept("No credential enrolled — read a document first.");
            return;
        }
        java.io.File g1 = new java.io.File(a.getExternalFilesDir(null), "g1_big.dat");
        if (!g1.exists()) {
            say.accept("Missing SRS (g1_big.dat) in app files dir.");
            return;
        }
        onProving.run();   // all checks passed — now it's safe to show the "sealing" progress stage
        // Biometric FIRST (P1.5): the sealed credential unwraps only within the
        // Seal auth window, so the strong biometric must precede witness
        // decryption. The same prompt authorizes the ephemeral device-sig key
        // (CryptoObject) — one fingerprint covers unseal + prove + sign.
        say.accept(c.display() + "\nConfirm with fingerprint to unseal & prove…");
        try {
            // Ephemeral per-presentation key: fresh, hardware-attested, deleted right
            // after sending. No persistent per-site key ⇒ no on-device record of which
            // sites you've answered (strengthens the "no logs anywhere" / double-anonymity story).
            final String alias = "kv-eph-" + Long.toString(
                    Math.abs(new java.security.SecureRandom().nextLong()), 36);
            final KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Attest.generate(alias, c.nonce, true);
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(((KeyStore.PrivateKeyEntry) ks.getEntry(alias, null)).getPrivateKey());
            BiometricPrompt prompt = new BiometricPrompt.Builder(a)
                    .setTitle("OneBit: answer one bit")
                    .setSubtitle(c.display())
                    .setNegativeButton("Refuse", a.getMainExecutor(),
                            (d, w) -> say.accept("Holder refused."))
                    .build();
            prompt.authenticate(new BiometricPrompt.CryptoObject(sig),
                    new CancellationSignal(), a.getMainExecutor(),
                    new BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                            proveAndSend(c, cred, ks, alias, r.getCryptoObject().getSignature(), g1, t0);
                        }

                        @Override
                        public void onAuthenticationError(int code, CharSequence msg) {
                            try { ks.deleteEntry(alias); } catch (Exception ignore) {} // don't leak the ephemeral key
                            say.accept("Auth error: " + msg);
                        }
                    });
        } catch (Exception e) {
            say.accept("FAIL (closed): " + e);
        }
    }

    /** Runs after the biometric: unseal (inside the Seal auth window), prove,
     *  sign with the already-authorized ephemeral key, send via browser. */
    private void proveAndSend(Challenge c, SharedPreferences cred, KeyStore ks,
                              String alias, Signature sig, java.io.File g1, long t0) {
        say.accept(amortized ? "Proving (amortized, ~0.8s)…"
                : "Proving (native, ~2.5s foreground)…");
        new Thread(() -> {
            android.os.PowerManager pm = a.getSystemService(android.os.PowerManager.class);
            android.os.PowerManager.WakeLock wl = pm.newWakeLock(
                    android.os.PowerManager.PARTIAL_WAKE_LOCK, "onebit:prove");
            try {
                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_DISPLAY);
                wl.acquire(120_000);

                String circuitName = amortized ? amortCircuit : "zk/" + faithfulCircuit + ".json";
                String circuit = readAsset(circuitName);
                String witness = amortized ? buildAmortizedWitness(c) : buildWitness(cred, c);
                android.util.Log.i("ONEBIT_PRESENT", "proving circuit=" + circuitName + " amortized=" + amortized);
                long p0 = System.currentTimeMillis();
                byte[] proofBytes = NativeProver.prove(circuit, witness, g1.getAbsolutePath(), false);
                long proveMs = System.currentTimeMillis() - p0;
                android.util.Log.i("ONEBIT_PRESENT", "PROVE OK " + circuitName + " in " + proveMs
                        + " ms, N=" + fieldHex(proofBytes, 3));

                // proofBytes = [public_inputs (5*32B)][proof]; keep whole so the
                // verifier can reconstruct {proof, publicInputs}. N is pub #3.
                String nullifier = fieldHex(proofBytes, 3);

                // person_bound is signed into the digest (below) so the verifier can
                // trust it; compute it once and reuse in the envelope.
                boolean personBound = new java.io.File(a.getFilesDir(), "personbound.txt").exists();
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(c.nonce);
                md.update(c.origin.getBytes(StandardCharsets.UTF_8));
                md.update(MessageDigest.getInstance("SHA-256").digest(proofBytes));
                md.update((byte) (personBound ? 1 : 0));
                sig.update(md.digest());
                byte[] deviceSig = sig.sign();   // completes the biometric-authorized op
                String response = envelope(c, alias, proofBytes, nullifier, deviceSig, personBound);
                try { ks.deleteEntry(alias); } catch (Exception ignore) {} // ephemeral: keep no trace
                String url = RETURN_URL + Base64.encodeToString(
                        response.getBytes(StandardCharsets.UTF_8),
                        Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
                a.runOnUiThread(() -> a.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))));
                say.accept("Presented in " + (System.currentTimeMillis() - t0)
                        + " ms (proof " + proveMs + " ms).");
            } catch (Throwable t) {
                android.util.Log.w("ONEBIT_PRESENT", "PROVE FAIL: " + t);
                say.accept("PROVE FAIL (closed): " + t);
                try { ks.deleteEntry(alias); } catch (Exception ignore) {} // don't leak the ephemeral key
            } finally {
                if (wl.isHeld()) wl.release();
            }
        }).start();
    }

    /** real persisted document witness (556 fields) + per-presentation
     *  [k, ctx, current, age_min]. */
    private String buildWitness(SharedPreferences cred, Challenge c) throws Exception {
        String doc = new String(Seal.readFile(
                new java.io.File(a.getFilesDir(), "docwit.txt").toPath()),
                StandardCharsets.UTF_8).trim();
        String k = new String(Seal.unwrap(Base64.decode(
                cred.getString("k", ""), Base64.NO_WRAP)), StandardCharsets.UTF_8);
        LocalDate today = LocalDate.now();
        int current = today.getYear() * 10000 + today.getMonthValue() * 100 + today.getDayOfMonth();
        return doc + "\n"
                + k + "\n"
                + Nullifier.ctx(c.verifierId, c.epoch) + "\n"
                + current + "\n"
                + c.value + "\n";
    }

    /** Amortized presentation witness: the 6 sealed credential fields
     *  (dob, expiry, doc_hash, k, salt, C) + per-challenge [ctx, current,
     *  age_min], in present_amortized's declaration order. */
    private String buildAmortizedWitness(Challenge c) throws Exception {
        // acred.bin = dob\nexpiry\ndoc_hash\nk\nsalt\nC (all decimal), SE-wrapped.
        String cred = new String(Seal.readFile(
                new java.io.File(a.getFilesDir(), "acred.bin").toPath()),
                StandardCharsets.UTF_8).trim();
        LocalDate today = LocalDate.now();
        int current = today.getYear() * 10000 + today.getMonthValue() * 100 + today.getDayOfMonth();
        return cred + "\n"
                + Nullifier.ctx(c.verifierId, c.epoch) + "\n"
                + current + "\n"
                + c.value + "\n";
    }

    private String envelope(Challenge c, String alias, byte[] proof, String nullifier,
                            byte[] deviceSig, boolean personBound) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        JSONArray chain = new JSONArray();
        for (Certificate cert : ks.getCertificateChain(alias)) {
            chain.put(Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP));
        }
        LocalDate today = LocalDate.now();
        int current = today.getYear() * 10000 + today.getMonthValue() * 100 + today.getDayOfMonth();
        JSONObject pi = new JSONObject()
                .put("T", today.format(DateTimeFormatter.BASIC_ISO_DATE))
                .put("N", nullifier)
                .put("ctx", Nullifier.ctx(c.verifierId, c.epoch).toString())
                .put("current", current)
                .put("age_min", c.value)
                .put("nonce", Base64.encodeToString(c.nonce, Base64.NO_WRAP))
                .put("origin", c.origin)
                .put("R_icao", "v1");
        return new JSONObject()
                .put("v", 1)
                .put("proof", Base64.encodeToString(proof, Base64.NO_WRAP))
                .put("public_inputs", pi)
                .put("device_sig", Base64.encodeToString(deviceSig, Base64.NO_WRAP))
                .put("attestation_chain", chain)
                .put("mode", "A")
                .put("tier", "A")
                .put("circuit", amortized
                        ? amortCircuit.substring(3, amortCircuit.length() - 5)  // zk/<name>.json -> <name>
                        : faithfulCircuit)
                // Amortized: provenance established at enrollment + attested (T3);
                // no per-presentation enroll proof. Faithful: dual-proof chain.
                .put("enroll_proof", amortized ? "" : enrollProofB64())
                .put("enroll_alg", amortized ? "" : enrollAlg())
                .put("binding", amortized ? "attested-enrollment" : "document")
                // person-bound only if a face-match enrollment marker was written (future,
                // regulated tier); today's credentials are bearer, so this is false. Signed
                // into device_sig (see proveAndSend) so a relay can't forge it.
                .put("person_bound", personBound)
                .toString();
    }

    // noir-rs proof: [uint32 num_public][public_inputs][proof]. Public input
    // `index` lives at 4 + index*32.
    /** persisted enroll proof (base64), or "" if none. */
    private String enrollProofB64() {
        try {
            byte[] p = Seal.readFile(
                    new java.io.File(a.getFilesDir(), "enrollproof.bin").toPath());
            return Base64.encodeToString(p, Base64.NO_WRAP);
        } catch (Exception e) { return ""; }
    }

    /** CSCA algorithm the enroll proof was made for (verifier picks the circuit
     *  + published root). Defaults to rsa4096. */
    private String enrollAlg() {
        try {
            return new String(java.nio.file.Files.readAllBytes(
                    new java.io.File(a.getFilesDir(), "enrollalg.txt").toPath()),
                    StandardCharsets.UTF_8).trim();
        } catch (Exception e) { return "rsa4096"; }
    }

    private static String fieldHex(byte[] flat, int index) {
        int off = 4 + index * 32;
        BigInteger v = new BigInteger(1, java.util.Arrays.copyOfRange(flat, off, off + 32));
        return v.toString();
    }

    private String readAsset(String path) throws Exception {
        try (java.io.InputStream in = a.getAssets().open(path)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}