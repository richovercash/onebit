// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * P1.5 wallet-side verifier-signature check. A challenge is authentic iff its
 * `sig` is a valid ECDSA signature, by the key whose SPKI-sha256 == verifier_id,
 * over the canonical signedContent(). Everything else must fail closed.
 */
public class ChallengeSigTest {

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(Character.forDigit((x >> 4) & 0xf, 16))
                          .append(Character.forDigit(x & 0xf, 16));
        return s.toString();
    }

    /** Build a signed challenge the way DemoServer does. */
    static String mint(KeyPair kp, int value, byte[] spkiOverride) throws Exception {
        byte[] spki = spkiOverride != null ? spkiOverride : kp.getPublic().getEncoded();
        String vid = hex(MessageDigest.getInstance("SHA-256").digest(spki));
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[32]);
        String origin = "https://demo.onebit.local", epoch = "2026-07-11";
        String signed = Challenge.signedContent(nonceB64, origin, vid, epoch,
                "age_gte", value, 1, "A", false);
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(kp.getPrivate());
        s.update(signed.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String sig = Base64.getEncoder().encodeToString(s.sign());
        return ("{\"v\":1,\"nonce\":\"%s\",\"origin\":\"%s\",\"verifier_id\":\"%s\",\"epoch\":\"%s\","
                + "\"policy\":{\"predicate\":\"age_gte\",\"value\":%d,\"icao_root_min_version\":1,"
                + "\"attestation\":{\"allowlist_url\":\"https://x\",\"allowlist_hash\":\"h\",\"tier\":\"A\"},"
                + "\"mode_b_accepted\":false},\"sig\":\"%s\",\"spki\":\"%s\"}")
                .formatted(nonceB64, origin, vid, epoch, value, sig,
                        Base64.getEncoder().encodeToString(spki));
    }

    static KeyPair ecKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    @Test
    public void authenticChallengeVerifies() throws Exception {
        assertTrue(Challenge.parse(mint(ecKey(), 18, null)).verifySig());
    }

    @Test
    public void tamperedValueFails() throws Exception {
        // Signed for value=18; flip the policy value to 21 in the wire text.
        String forged = mint(ecKey(), 18, null).replace("\"value\":18", "\"value\":21");
        assertFalse(Challenge.parse(forged).verifySig());
    }

    @Test
    public void wrongKeyForVerifierIdFails() throws Exception {
        // sig+verifier_id are from key A, but spki carries key B: sha256(spki) no
        // longer matches verifier_id, and the sig wouldn't verify under B either.
        KeyPair a = ecKey(), b = ecKey();
        String forged = mint(a, 18, b.getPublic().getEncoded());
        assertFalse(Challenge.parse(forged).verifySig());
    }
}