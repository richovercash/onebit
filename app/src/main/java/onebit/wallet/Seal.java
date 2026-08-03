// SPDX-License-Identifier: AGPL-3.0-only
package onebit.wallet;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * Secure-element wrap for persisted secrets (P1.5). Hybrid envelope: each blob
 * is encrypted under a fresh in-memory AES-256-GCM key, which is itself wrapped
 * by an RSA-2048-OAEP keypair in the AndroidKeyStore (StrongBox where present).
 * The split matters:
 *  - SEAL uses only the public half — enrollment never needs an auth prompt.
 *  - UNSEAL uses the non-exportable private half, which is auth-gated: a
 *    Class-3 biometric within the last AUTH_WINDOW_S seconds is required, or
 *    the SE refuses. Present's fingerprint prompt (moved ahead of witness
 *    decryption) satisfies it; on-device malware can no longer silently ask
 *    the SE to decrypt (self-review F2 residual closed), and files pulled off
 *    the device were already worthless.
 *
 * Blobs from the pre-auth AES scheme (alias "onebit-seal") still unwrap via
 * the legacy path and are transparently re-sealed on read.
 *
 * ponytail: a 300 s auth window, not per-use CryptoObject auth — per-use costs
 * one prompt per unwrapped blob (the faithful path unwraps two). Upgrade path
 * if that matters: merge the credential files into one sealed blob and pass a
 * CryptoObject(Cipher) through the presentation prompt.
 */
final class Seal {

    private static final String ALIAS = "onebit-seal2";        // RSA-2048, auth-gated private half
    private static final String LEGACY_ALIAS = "onebit-seal";  // v1 AES key, no auth gate
    private static final byte[] MAGIC = {'O', 'B', '2', 0};
    private static final int AUTH_WINDOW_S = 300;
    private static final int IV_LEN = 12;        // GCM standard nonce
    private static final int TAG_BITS = 128;
    // Keystore RSA keys historically authorize MGF1-SHA1 only; pin it on both
    // sides so encrypt (JCE) and decrypt (keystore) agree. OAEP digest is SHA-256.
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);

    private Seal() {}

    private static KeyStore ks() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return ks;
    }

    private static PublicKey pub() throws Exception {
        KeyStore ks = ks();
        if (!ks.containsAlias(ALIAS)) generate();
        return ks.getCertificate(ALIAS).getPublicKey();
    }

    private static void generate() throws Exception {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                .setUserAuthenticationRequired(true);
        if (Build.VERSION.SDK_INT >= 30) {
            b.setUserAuthenticationParameters(AUTH_WINDOW_S, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            b.setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_S);
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        try {
            kpg.initialize(b.setIsStrongBoxBacked(true).build());
            kpg.generateKeyPair();
        } catch (Exception noStrongBox) {   // device without a StrongBox chip
            kpg.initialize(b.setIsStrongBoxBacked(false).build());
            kpg.generateKeyPair();
        }
    }

    /** [MAGIC][2B wrapped-key len][RSA-OAEP(aes key)][12B IV][ciphertext+tag]. */
    static byte[] wrap(byte[] plain) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aes = kg.generateKey();
        Cipher g = Cipher.getInstance("AES/GCM/NoPadding");
        g.init(Cipher.ENCRYPT_MODE, aes);
        byte[] iv = g.getIV();
        byte[] ct = g.doFinal(plain);
        Cipher r = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        r.init(Cipher.ENCRYPT_MODE, pub(), OAEP);   // public half: no auth needed
        byte[] wk = r.doFinal(aes.getEncoded());
        byte[] out = new byte[MAGIC.length + 2 + wk.length + iv.length + ct.length];
        int o = 0;
        System.arraycopy(MAGIC, 0, out, o, MAGIC.length); o += MAGIC.length;
        out[o++] = (byte) (wk.length >> 8);
        out[o++] = (byte) wk.length;
        System.arraycopy(wk, 0, out, o, wk.length); o += wk.length;
        System.arraycopy(iv, 0, out, o, iv.length); o += iv.length;
        System.arraycopy(ct, 0, out, o, ct.length);
        return out;
    }

    /** Throws UserNotAuthenticatedException when no strong biometric happened
     *  within the auth window — callers fail closed (Present prompts first). */
    static byte[] unwrap(byte[] blob) throws Exception {
        if (blob.length > MAGIC.length + 2
                && Arrays.equals(Arrays.copyOf(blob, MAGIC.length), MAGIC)) {
            int o = MAGIC.length;
            int wkLen = ((blob[o] & 0xff) << 8) | (blob[o + 1] & 0xff);
            o += 2;
            Cipher r = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            r.init(Cipher.DECRYPT_MODE, ks().getKey(ALIAS, null), OAEP);  // auth-gated
            byte[] aes = r.doFinal(blob, o, wkLen);
            o += wkLen;
            Cipher g = Cipher.getInstance("AES/GCM/NoPadding");
            g.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aes, "AES"),
                    new GCMParameterSpec(TAG_BITS, blob, o, IV_LEN));
            return g.doFinal(blob, o + IV_LEN, blob.length - o - IV_LEN);
        }
        // v1 blob: [12B IV][ciphertext+tag] under the legacy non-auth-gated AES key.
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, ks().getKey(LEGACY_ALIAS, null),
                new GCMParameterSpec(TAG_BITS, blob, 0, IV_LEN));
        return c.doFinal(blob, IV_LEN, blob.length - IV_LEN);
    }

    // File convenience.
    static void writeFile(Path p, byte[] plain) throws Exception { Files.write(p, wrap(plain)); }

    static byte[] readFile(Path p) throws Exception {
        byte[] blob = Files.readAllBytes(p);
        byte[] plain = unwrap(blob);
        if (!Arrays.equals(Arrays.copyOf(blob, MAGIC.length), MAGIC)) {
            try { Files.write(p, wrap(plain)); } catch (Exception ignore) {}  // migrate v1 → v2
        }
        return plain;
    }
}
