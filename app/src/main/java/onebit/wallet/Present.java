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
 * refusal check -> build monolithic witness -> native UltraHonk proof (real
 * RSA passive-auth + predicate + nullifier in one circuit) -> biometric ->
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
    private boolean amortized;   // Tier A fast path: acred.bin enrolled

    Present(Activity a, Consumer<String> say) {
        this.a = a;
        this.say = say;
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
        if (NativeProver.loadError != null) {
            say.accept("Native prover unavailable: " + NativeProver.loadError);
            return;
        }
        SharedPreferences cred = a.getSharedPreferences("cred", Context.MODE_PRIVATE);
        // Prefer the amortized Tier A path (~0.8s) if its credential is enrolled;
        // fall back to the faithful mono path (~2.5s, full CMS passive auth).
        amortized = new java.io.File(a.getFilesDir(), "acred.bin").exists();
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
        say.accept(c.display() + (amortized ? "\nProving (amortized, ~0.8s)…"
                : "\nProving (native, ~2.5s foreground)…"));

        new Thread(() -> {
            android.os.PowerManager pm = a.getSystemService(android.os.PowerManager.class);
            android.os.PowerManager.WakeLock wl = pm.newWakeLock(
                    android.os.PowerManager.PARTIAL_WAKE_LOCK, "onebit:prove");
            try {
                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_DISPLAY);
                wl.acquire(120_000);

                String circuit = readAsset(amortized ? "zk/present_amortized.json" : CIRCUIT);
                String witness = amortized ? buildAmortizedWitness(c) : buildWitness(cred, c);
                long p0 = System.currentTimeMillis();
                byte[] proofBytes = NativeProver.prove(circuit, witness, g1.getAbsolutePath(), false);
                long proveMs = System.currentTimeMillis() - p0;

                // proofBytes = [public_inputs (5*32B)][proof]; keep whole so the
                // verifier can reconstruct {proof, publicInputs}. N is pub #3.
                String nullifier = fieldHex(proofBytes, 3);
                say.accept("Proof in " + proveMs + " ms. Confirm with fingerprint.");
                a.runOnUiThread(() -> signAndSend(c, proofBytes, nullifier, proveMs, t0));
            } catch (Throwable t) {
                say.accept("PROVE FAIL (closed): " + t);
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

    private void signAndSend(Challenge c, byte[] proof, String nullifier, long proveMs, long t0) {
        try {
            String alias = "kv-" + c.verifierId;
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (!ks.containsAlias(alias)) Attest.generate(alias, c.nonce, true);

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
                            try {
                                MessageDigest md = MessageDigest.getInstance("SHA-256");
                                md.update(c.nonce);
                                md.update(c.origin.getBytes(StandardCharsets.UTF_8));
                                md.update(MessageDigest.getInstance("SHA-256").digest(proof));
                                Signature s = r.getCryptoObject().getSignature();
                                s.update(md.digest());
                                String response = envelope(c, alias, proof, nullifier, s.sign());
                                String url = RETURN_URL + Base64.encodeToString(
                                        response.getBytes(StandardCharsets.UTF_8),
                                        Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
                                a.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
                                say.accept("Presented in " + (System.currentTimeMillis() - t0)
                                        + " ms (proof " + proveMs + " ms).");
                            } catch (Exception e) {
                                say.accept("FAIL (closed): " + e);
                            }
                        }

                        @Override
                        public void onAuthenticationError(int code, CharSequence msg) {
                            say.accept("Auth error: " + msg);
                        }
                    });
        } catch (Exception e) {
            say.accept("FAIL (closed): " + e);
        }
    }

    private String envelope(Challenge c, String alias, byte[] proof, String nullifier,
                            byte[] deviceSig) throws Exception {
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
                .put("circuit", amortized ? "present_amortized" : "mono_faithful")
                // Amortized: provenance established at enrollment + attested (T3);
                // no per-presentation enroll proof. Faithful: dual-proof chain.
                .put("enroll_proof", amortized ? "" : enrollProofB64())
                .put("enroll_alg", amortized ? "" : enrollAlg())
                .put("binding", amortized ? "attested-enrollment" : "document")
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
