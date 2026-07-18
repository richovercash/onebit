package onebit.wallet;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricPrompt;
import android.net.Uri;
import android.os.CancellationSignal;
import android.util.Base64;

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
 * P0 presentation (T5 pass 2): refusal check -> display -> on-device
 * UltraHonk proof (Circuit P v0) -> biometric -> device_sig over
 * H(nonce || origin || SHA256(proof)) -> response via browser.
 */
final class Present implements ZkProver.Callback {

    static final String RETURN_URL = "http://localhost:8317/present?r=";

    private final Activity a;
    private final Consumer<String> say;
    private ZkProver prover;
    private Challenge c;
    private long t0;
    private boolean proverReady;
    private String pendingInputs;

    Present(Activity a, Consumer<String> say) {
        this.a = a;
        this.say = say;
    }

    void start(String challengeJson) {
        t0 = System.currentTimeMillis();
        try {
            c = Challenge.parse(challengeJson);
        } catch (Challenge.RefusalException e) {
            say.accept("REFUSED (V5): " + e.getMessage());
            return;
        }
        SharedPreferences cred = a.getSharedPreferences("cred", Context.MODE_PRIVATE);
        if (!cred.contains("dob")) {
            say.accept("No credential enrolled — read a document first (T1 flow).");
            return;
        }
        say.accept(c.display() + "\nGenerating proof…");
        LocalDate today = LocalDate.now();
        int current = today.getYear() * 10000 + today.getMonthValue() * 100 + today.getDayOfMonth();
        JSONObject inputs;
        try {
            inputs = new JSONObject()
                    .put("dob", cred.getInt("dob", 0))
                    .put("expiry", cred.getInt("exp", 0))
                    .put("k", cred.getString("k", "0"))
                    .put("ctx", Nullifier.ctx(c.verifierId, c.epoch).toString())
                    .put("current", current)
                    .put("age_min", c.value);
        } catch (Exception e) {
            say.accept("FAIL (closed): " + e);
            return;
        }
        pendingInputs = inputs.toString();
        if (prover == null) {
            prover = new ZkProver(a, this); // warmup fires onReady
        } else if (proverReady) {
            prover.proveB64(pendingInputs);
        }
    }

    @Override
    public void onReady(String backendType) {
        proverReady = true;
        say.accept("Prover ready (" + backendType + "), proving…");
        if (pendingInputs != null) prover.proveB64(pendingInputs);
    }

    @Override
    public void onProof(String resultJson) {
        try {
            JSONObject r = new JSONObject(resultJson);
            byte[] proof = Base64.decode(r.getString("proof"), Base64.DEFAULT);
            JSONArray publicInputs = r.getJSONArray("publicInputs");
            long proveMs = r.getLong("ms");
            say.accept("Proof generated in " + proveMs + " ms (" + proof.length
                    + " B). Confirm with fingerprint.");
            signAndSend(proof, publicInputs, proveMs);
        } catch (Exception e) {
            say.accept("FAIL (closed): " + e);
        }
    }

    @Override
    public void onError(String message) {
        // an unsatisfiable witness (expired doc, underage) lands here: fail closed
        say.accept("PROOF FAIL (closed): " + message);
    }

    private void signAndSend(byte[] proof, JSONArray publicInputs, long proveMs) throws Exception {
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
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult res) {
                        try {
                            MessageDigest md = MessageDigest.getInstance("SHA-256");
                            md.update(c.nonce);
                            md.update(c.origin.getBytes(StandardCharsets.UTF_8));
                            md.update(MessageDigest.getInstance("SHA-256").digest(proof));
                            Signature s = res.getCryptoObject().getSignature();
                            s.update(md.digest());
                            String response = envelope(c, alias, proof, publicInputs, s.sign());
                            String url = RETURN_URL + Base64.encodeToString(
                                    response.getBytes(StandardCharsets.UTF_8),
                                    Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
                            a.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
                            say.accept("Presented in " + (System.currentTimeMillis() - t0)
                                    + " ms total (proof " + proveMs + " ms).");
                        } catch (Exception e) {
                            say.accept("FAIL (closed): " + e);
                        }
                    }

                    @Override
                    public void onAuthenticationError(int code, CharSequence msg) {
                        say.accept("Auth error: " + msg);
                    }
                });
    }

    private String envelope(Challenge c, String alias, byte[] proof,
                            JSONArray publicInputs, byte[] deviceSig) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        JSONArray chain = new JSONArray();
        for (Certificate cert : ks.getCertificateChain(alias)) {
            chain.put(Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP));
        }
        JSONObject pi = new JSONObject()
                .put("T", LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE))
                .put("N", publicInputs.getString(3))
                .put("ctx", Nullifier.ctx(c.verifierId, c.epoch).toString())
                .put("nonce", Base64.encodeToString(c.nonce, Base64.NO_WRAP))
                .put("origin", c.origin)
                .put("R_icao", "v1")
                .put("zk", publicInputs);
        return new JSONObject()
                .put("v", 1)
                .put("proof", Base64.encodeToString(proof, Base64.NO_WRAP))
                .put("public_inputs", pi)
                .put("device_sig", Base64.encodeToString(deviceSig, Base64.NO_WRAP))
                .put("attestation_chain", chain)
                .put("mode", "A")
                .put("tier", "A")
                .put("binding", "P-only") // pi_E recursion pending; labeled (V6)
                .toString();
    }
}
