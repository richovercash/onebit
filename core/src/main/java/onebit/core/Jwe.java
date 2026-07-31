// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.io.ByteArrayOutputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The crypto core of an ISO 18013-7 `direct_post.jwt` response: ECDH-ES key
 * agreement + Concat-KDF (NIST SP 800-56A) + AES-GCM — exactly the JWE the CA
 * Wallet posts back. Pure JCE, no Android/JSON deps, so it unit-tests on the JVM
 * against the RFC 7518 Appendix C vector (see JweTest).
 *
 * ponytail: only the ECDH-ES *direct* case (empty encrypted_key) and A*GCM enc,
 * which is what OID4VP mandates. Add key-wrap (ECDH-ES+A128KW) only if a wallet
 * demands it.
 */
public final class Jwe {
    private Jwe() {}

    /** Raw ECDH shared secret Z (the x-coord), per RFC 7518 §4.6. */
    public static byte[] ecdh(ECPrivateKey priv, ECPublicKey epk) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(priv);
        ka.doPhase(epk, true);
        return ka.generateSecret();
    }

    /** Concat-KDF (single-step, SHA-256) → the AES key, per RFC 7518 §4.6 / SP 800-56A.
     *  algId is the JWE "enc" value (e.g. "A128GCM"); apu/apv are the decoded
     *  PartyUInfo/PartyVInfo (empty allowed). SuppPubInfo = keyBits. */
    public static byte[] concatKdf(byte[] z, int keyBits, String algId, byte[] apu, byte[] apv) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        int reps = (keyBits + 255) / 256;
        ByteArrayOutputStream okm = new ByteArrayOutputStream();
        for (int i = 1; i <= reps; i++) {
            md.update(int32(i));
            md.update(z);
            md.update(lenPrefixed(algId.getBytes("US-ASCII")));  // AlgorithmID
            md.update(lenPrefixed(apu == null ? new byte[0] : apu)); // PartyUInfo
            md.update(lenPrefixed(apv == null ? new byte[0] : apv)); // PartyVInfo
            md.update(int32(keyBits));                            // SuppPubInfo
            // SuppPrivInfo: empty
            okm.write(md.digest());
        }
        byte[] full = okm.toByteArray();
        byte[] key = new byte[keyBits / 8];
        System.arraycopy(full, 0, key, 0, key.length);
        return key;
    }

    /** derive(priv, epk) = concatKdf(ecdh(...)) — the CEK for a direct ECDH-ES JWE. */
    public static byte[] derive(ECPrivateKey priv, ECPublicKey epk, int keyBits, String enc, byte[] apu, byte[] apv) throws Exception {
        return concatKdf(ecdh(priv, epk), keyBits, enc, apu, apv);
    }

    /** AES-GCM decrypt with the JWE protected header (ASCII base64url) as AAD. */
    public static byte[] gcmDecrypt(byte[] cek, byte[] iv, byte[] ct, byte[] tag, byte[] aad) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(tag.length * 8, iv));
        c.updateAAD(aad);
        byte[] in = new byte[ct.length + tag.length];
        System.arraycopy(ct, 0, in, 0, ct.length);
        System.arraycopy(tag, 0, in, ct.length, tag.length);
        return c.doFinal(in);
    }

    static byte[] int32(int n) {
        return new byte[]{(byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n};
    }

    static byte[] lenPrefixed(byte[] b) {
        byte[] out = new byte[4 + b.length];
        byte[] len = int32(b.length);
        System.arraycopy(len, 0, out, 0, 4);
        System.arraycopy(b, 0, out, 4, b.length);
        return out;
    }
}