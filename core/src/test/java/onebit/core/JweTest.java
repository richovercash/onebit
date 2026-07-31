// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

public class JweTest {

    /** RFC 7518 Appendix C: the published shared secret Z, with apu="Alice"/apv="Bob",
     *  enc=A128GCM, keydatalen=128, must Concat-KDF to the published derived key.
     *  Validates the OtherInfo assembly + digest loop against the spec's own vector.
     *  (Z is fed directly so the check doesn't hinge on EC key transcription.) */
    @Test public void rfc7518_appendixC_concatKdf() throws Exception {
        int[] zi = {158,86,217,29,129,113,53,211,114,131,66,131,191,132,38,156,
                    251,49,110,163,218,128,106,72,246,218,167,121,140,254,144,196};
        byte[] z = new byte[zi.length];
        for (int i = 0; i < zi.length; i++) z[i] = (byte) zi[i];
        byte[] k = Jwe.concatKdf(z, 128, "A128GCM", "Alice".getBytes("US-ASCII"), "Bob".getBytes("US-ASCII"));
        assertArrayEquals(Base64.getUrlDecoder().decode("VqqN6vgjbSBcIijNcacQGg"), k);
    }

    /** End-to-end wiring: a sender ephemeral + recipient static key must agree on the
     *  same CEK via Jwe.derive (ECDH symmetry), and Jwe.gcmDecrypt must recover what
     *  GCM-encrypt produced. Exercises ecdh() + derive() + gcmDecrypt() together. */
    @Test public void roundTrip_ecdhEs_gcm() throws Exception {
        KeyPair recip = ec(), eph = ec();
        byte[] apu = "onebit".getBytes("US-ASCII"), apv = new byte[0];
        byte[] cekEnc = Jwe.derive((ECPrivateKey) eph.getPrivate(), (ECPublicKey) recip.getPublic(), 128, "A128GCM", apu, apv);
        byte[] cekDec = Jwe.derive((ECPrivateKey) recip.getPrivate(), (ECPublicKey) eph.getPublic(), 128, "A128GCM", apu, apv);
        assertArrayEquals(cekEnc, cekDec);  // ECDH-ES both directions agree

        byte[] aad = "eyJwcm90ZWN0ZWQi".getBytes("US-ASCII");  // stand-in protected header
        byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);
        byte[] pt = "{\"vp_token\":\"...\"}".getBytes("UTF-8");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cekEnc, "AES"), new GCMParameterSpec(128, iv));
        c.updateAAD(aad);
        byte[] out = c.doFinal(pt);                       // ct||tag
        byte[] ct = new byte[out.length - 16], tag = new byte[16];
        System.arraycopy(out, 0, ct, 0, ct.length);
        System.arraycopy(out, ct.length, tag, 0, 16);

        assertArrayEquals(pt, Jwe.gcmDecrypt(cekDec, iv, ct, tag, aad));
    }

    static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }
}