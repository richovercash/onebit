// SPDX-License-Identifier: AGPL-3.0-only
package onebit.wallet;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Secure-element wrap for persisted secrets (P1.5). The AES-256-GCM key lives in
 * the AndroidKeyStore (StrongBox where present) and is non-exportable: pulling
 * the ciphertext files off the device yields nothing without the SE. This is the
 * interim mitigation for self-review F2 — an attacker can no longer lift the
 * document witness / nullifier key `k` and drive a custom prover with a varying
 * `k`.
 *
 * ponytail: not per-use auth-gated. That defeats offline file extraction, which
 * is the F2 threat; it does NOT defeat on-device malware asking the SE to
 * decrypt. Upgrade path when that's in scope: add
 * setUserAuthenticationRequired(true) here and move the biometric prompt ahead
 * of witness decryption in Present.
 */
final class Seal {

    private static final String ALIAS = "onebit-seal";
    private static final int IV_LEN = 12;        // GCM standard nonce
    private static final int TAG_BITS = 128;

    private Seal() {}

    private static SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(ALIAS)) {
            return ((KeyStore.SecretKeyEntry) ks.getEntry(ALIAS, null)).getSecretKey();
        }
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256);
        KeyGenerator kg = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        try {
            kg.init(b.setIsStrongBoxBacked(true).build());
            return kg.generateKey();
        } catch (Exception noStrongBox) {   // device without a StrongBox chip
            kg.init(b.setIsStrongBoxBacked(false).build());
            return kg.generateKey();
        }
    }

    /** [12B IV][ciphertext+tag]. */
    static byte[] wrap(byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key());
        byte[] iv = c.getIV();                         // SE-generated random IV
        byte[] ct = c.doFinal(plain);
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return out;
    }

    static byte[] unwrap(byte[] blob) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key(),
                new GCMParameterSpec(TAG_BITS, blob, 0, IV_LEN));
        return c.doFinal(blob, IV_LEN, blob.length - IV_LEN);
    }

    // File convenience.
    static void writeFile(Path p, byte[] plain) throws Exception { Files.write(p, wrap(plain)); }
    static byte[] readFile(Path p) throws Exception { return unwrap(Files.readAllBytes(p)); }
}