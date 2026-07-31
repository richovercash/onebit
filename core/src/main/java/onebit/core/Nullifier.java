// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Canonical derivation of the nullifier context ctx = H(verifier_id ‖ epoch),
 * a public input to the presentation circuit. Wallet and verifier SDK MUST
 * compute this identically; the circuit then proves
 * N = Poseidon2(k, ctx) without revealing k (SPEC §4.1).
 */
public final class Nullifier {

    /** BN254 scalar field modulus (the proving field). */
    public static final BigInteger P = new BigInteger(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617");

    public static BigInteger ctx(String verifierId, String epoch) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(verifierId.getBytes(StandardCharsets.UTF_8));
            md.update((byte) 0);
            md.update(epoch.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(1, md.digest()).mod(P);
        } catch (Exception e) {
            throw new IllegalStateException(e); // SHA-256 always present
        }
    }

    private Nullifier() {}
}