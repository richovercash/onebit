package onebit.wallet;

import android.app.Activity;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Base64;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.function.Consumer;

/**
 * T3: per-verifier SE key (K_v), StrongBox where available, auth-bound,
 * attested with the verifier's challenge. Exports chain.pem + nonce.bin +
 * sig.bin to the app's external files dir for the desktop verifier CLI.
 */
final class Attest {

    /** Demo challenge; in T4 this arrives in the verifier's challenge message. */
    static final byte[] DEMO_NONCE =
            "onebit-demo-nonce-0001".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    static void run(Activity a, String verifierId, Consumer<String> say) {
        try {
            String alias = "kv-" + verifierId;
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (!ks.containsAlias(alias)) {
                say.accept("Generating K_v (" + alias + ")…");
                generate(alias, DEMO_NONCE, true);
            }

            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(((KeyStore.PrivateKeyEntry) ks.getEntry(alias, null)).getPrivateKey());

            BiometricPrompt prompt = new BiometricPrompt.Builder(a)
                    .setTitle("OneBit: unlock K_v")
                    .setSubtitle("verifier: " + verifierId)
                    .setNegativeButton("Cancel", a.getMainExecutor(), (d, w) ->
                            say.accept("Attest cancelled."))
                    .build();
            prompt.authenticate(new BiometricPrompt.CryptoObject(sig),
                    new CancellationSignal(), a.getMainExecutor(),
                    new BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(
                                BiometricPrompt.AuthenticationResult result) {
                            try {
                                Signature s = result.getCryptoObject().getSignature();
                                s.update(DEMO_NONCE);
                                byte[] signature = s.sign();
                                export(a, alias, signature);
                                say.accept("ATTEST OK — chain.pem/nonce.bin/sig.bin exported.\n"
                                        + "adb pull /sdcard/Android/data/onebit.wallet/files/");
                            } catch (Exception e) {
                                say.accept("Attest FAIL (closed): " + e);
                            }
                        }

                        @Override
                        public void onAuthenticationError(int code, CharSequence msg) {
                            say.accept("Auth error: " + msg);
                        }
                    });
        } catch (Exception e) {
            say.accept("Attest FAIL (closed): " + e);
        }
    }

    /** Per-verifier K_v: attestation binds the first-contact challenge (§4.3). */
    static void generate(String alias, byte[] challenge, boolean tryStrongBox) throws Exception {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .setUserAuthenticationRequired(true);
        if (Build.VERSION.SDK_INT >= 30) {
            b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        }
        if (tryStrongBox) b.setIsStrongBoxBacked(true);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        try {
            kpg.initialize(b.build());
            kpg.generateKeyPair();
        } catch (StrongBoxUnavailableException e) {
            generate(alias, challenge, false); // ponytail: fallback = TEE; tier recorded by verifier
        }
    }

    private static void export(Activity a, String alias, byte[] signature) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Certificate[] chain = ks.getCertificateChain(alias);
        File dir = a.getExternalFilesDir(null);
        try (FileOutputStream f = new FileOutputStream(new File(dir, "chain.pem"))) {
            for (Certificate c : chain) {
                f.write("-----BEGIN CERTIFICATE-----\n".getBytes());
                f.write(Base64.encode(c.getEncoded(), Base64.DEFAULT));
                f.write("-----END CERTIFICATE-----\n".getBytes());
            }
        }
        try (FileOutputStream f = new FileOutputStream(new File(dir, "nonce.bin"))) {
            f.write(DEMO_NONCE);
        }
        try (FileOutputStream f = new FileOutputStream(new File(dir, "sig.bin"))) {
            f.write(signature);
        }
        Toast.makeText(a, "exported to " + dir, Toast.LENGTH_LONG).show();
    }

    private Attest() {}
}
