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
    static final int WIT_K = 424, WIT_CTX = 425, WIT_CUR = 426, WIT_AGE = 427;

    private final Activity a;
    private final Consumer<String> say;

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
        if (NativeProver.loadError != null) {
            say.accept("Native prover unavailable: " + NativeProver.loadError);
            return;
        }
        SharedPreferences cred = a.getSharedPreferences("cred", Context.MODE_PRIVATE);
        if (!cred.contains("k")) {
            say.accept("No credential enrolled — read a document first.");
            return;
        }
        java.io.File g1 = new java.io.File(a.getExternalFilesDir(null), "g1_big.dat");
        if (!g1.exists()) {
            say.accept("Missing SRS (g1_big.dat) in app files dir.");
            return;
        }
        say.accept(c.display() + "\nProving (native, ~2.5s foreground)…");

        new Thread(() -> {
            android.os.PowerManager pm = a.getSystemService(android.os.PowerManager.class);
            android.os.PowerManager.WakeLock wl = pm.newWakeLock(
                    android.os.PowerManager.PARTIAL_WAKE_LOCK, "onebit:prove");
            try {
                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_DISPLAY);
                wl.acquire(120_000);

                String circuit = readAsset("zk/mono_slim.json");
                String witness = buildWitness(cred, c);
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

    /** doc witness (persisted) + per-presentation [k, ctx, current, age_min]. */
    private String buildWitness(SharedPreferences cred, Challenge c) throws Exception {
        String[] w = readAsset("zk/wit_slim.txt").trim().split("\n");
        LocalDate today = LocalDate.now();
        int current = today.getYear() * 10000 + today.getMonthValue() * 100 + today.getDayOfMonth();
        w[WIT_K] = cred.getString("k", "0");
        w[WIT_CTX] = Nullifier.ctx(c.verifierId, c.epoch).toString();
        w[WIT_CUR] = String.valueOf(current);
        w[WIT_AGE] = String.valueOf(c.value);
        return String.join("\n", w);
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
                .put("circuit", "mono_slim")
                .put("binding", "rsa-in-circuit") // real RSA PA in-circuit; faithful CMS + real merkle pending
                .toString();
    }

    // noir-rs proof: [uint32 num_public][public_inputs][proof]. Public input
    // `index` lives at 4 + index*32.
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
