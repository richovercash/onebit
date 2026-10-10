// SPDX-License-Identifier: AGPL-3.0-only
package onebit.verifier;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;

/**
 * Raw Android key attestation verification per SPEC §5 — V4: allowlist of
 * roots and verified-boot keys, no platform policy service, fully offline.
 * Fail-closed: any defect throws.
 */
public final class AttestationVerifier {

    static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    // AuthorizationList tags (KeyMint schema)
    static final int TAG_PURPOSE = 1;
    static final int TAG_NO_AUTH_REQUIRED = 503;
    static final int TAG_ORIGIN = 702;
    static final int TAG_ATTESTATION_APPLICATION_ID = 709;
    static final int PURPOSE_SIGN = 2;
    static final int ORIGIN_GENERATED = 0;
    static final int TAG_ROOT_OF_TRUST = 704;
    static final int TAG_OS_PATCH_LEVEL = 706;

    public static final class Result {
        public String bootState;
        public String bootKeySha256Hex;
        public int osPatchLevel;
        public boolean userAuthRequired;
        public int securityLevel; // 1=TEE 2=StrongBox
        public String rootName;
        public String bootPolicyName;
        public String appPackage;

        @Override
        public String toString() {
            return String.format(
                "root=%s securityLevel=%s bootState=%s bootPolicy=%s%n"
                + "bootKey(sha256)=%s%n"
                + "osPatchLevel=%d userAuthRequired=%b",
                rootName, securityLevel == 2 ? "StrongBox" : (securityLevel == 1 ? "TEE" : "SW!"),
                bootState, bootPolicyName, bootKeySha256Hex, osPatchLevel, userAuthRequired);
        }
    }

    /** chain[0] = leaf (K_v). Throws on any policy violation. */
    public static Result verify(List<X509Certificate> chain, byte[] expectedChallenge,
                                JsonObject allowlist) throws Exception {
        if (chain.size() < 2) throw new IllegalStateException("chain too short");

        // 1. Signature chain: each cert signed by its successor, root self-signed.
        //    Every issuer must be a CA allowed to sign certs, and only the leaf may
        //    carry the attestation extension: otherwise any ordinary attested key
        //    could sign a forged "StrongBox / locked / Verified" leaf for a software
        //    key and the forgery would chain to the real root.
        for (int i = 0; i < chain.size() - 1; i++) {
            chain.get(i).verify(chain.get(i + 1).getPublicKey());
        }
        X509Certificate root = chain.get(chain.size() - 1);
        root.verify(root.getPublicKey());
        if (chain.get(0).getBasicConstraints() != -1) {
            throw new IllegalStateException("attested leaf is a CA certificate");
        }
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            c.checkValidity();
            if (i == 0) continue;
            boolean[] ku = c.getKeyUsage();
            if (c.getBasicConstraints() == -1 || ku == null || !ku[5]) {
                throw new IllegalStateException("chain[" + i + "] is not a CA with keyCertSign");
            }
            if (c.getExtensionValue(ATTESTATION_OID) != null) {
                throw new IllegalStateException("attestation extension on non-leaf chain[" + i + "]");
            }
        }

        // 2. Root SPKI must be allowlisted (V4).
        String rootSpki = sha256Hex(root.getPublicKey().getEncoded());
        Result r = new Result();
        for (var e : allowlist.getAsJsonArray("roots")) {
            JsonObject o = e.getAsJsonObject();
            if (o.get("spki_sha256").getAsString().equalsIgnoreCase(rootSpki)) {
                r.rootName = o.get("name").getAsString();
            }
        }
        if (r.rootName == null) {
            throw new IllegalStateException("attestation root not in allowlist: " + rootSpki);
        }

        // 3. Parse the attestation extension on the leaf.
        byte[] extValue = chain.get(0).getExtensionValue(ATTESTATION_OID);
        if (extValue == null) throw new IllegalStateException("no attestation extension on leaf");
        byte[] extDer = ASN1OctetString.getInstance(extValue).getOctets();
        ASN1Sequence att = ASN1Sequence.getInstance(extDer);

        r.securityLevel = ASN1Enumerated.getInstance(att.getObjectAt(1)).intValueExact();
        if (r.securityLevel < 1) throw new IllegalStateException("software-level attestation rejected");

        byte[] challenge = ASN1OctetString.getInstance(att.getObjectAt(4)).getOctets();
        // null = caller accepts any keygen-time challenge (K_v attested at first
        // contact; per-presentation freshness is the device_sig's job, §4.3)
        if (expectedChallenge != null && !MessageDigest.isEqual(challenge, expectedChallenge)) {
            throw new IllegalStateException("attestation challenge mismatch");
        }

        // 4. Hardware-enforced authorization list (last element).
        ASN1Sequence hwEnforced = ASN1Sequence.getInstance(att.getObjectAt(7));
        boolean noAuthRequired = false;
        boolean canSign = false;
        Integer origin = null;
        ASN1Sequence rootOfTrust = null;
        for (var el : hwEnforced) {
            ASN1TaggedObject t = ASN1TaggedObject.getInstance(el);
            switch (t.getTagNo()) {
                case TAG_PURPOSE -> {
                    for (var p : ASN1Set.getInstance(t.getExplicitBaseObject())) {
                        canSign |= ASN1Integer.getInstance(p).intValueExact() == PURPOSE_SIGN;
                    }
                }
                case TAG_ORIGIN ->
                    origin = ASN1Integer.getInstance(t.getExplicitBaseObject()).intValueExact();
                case TAG_NO_AUTH_REQUIRED -> noAuthRequired = true;
                case TAG_ROOT_OF_TRUST -> rootOfTrust = ASN1Sequence.getInstance(t.getExplicitBaseObject());
                case TAG_OS_PATCH_LEVEL ->
                    r.osPatchLevel = ASN1Integer.getInstance(t.getExplicitBaseObject()).intValueExact();
                default -> { }
            }
        }
        r.userAuthRequired = !noAuthRequired;
        if (rootOfTrust == null) throw new IllegalStateException("no RootOfTrust in hw-enforced list");
        // An IMPORTED key existed outside the secure hardware: attestation proves nothing.
        if (origin == null || origin != ORIGIN_GENERATED) {
            throw new IllegalStateException("key origin not GENERATED in hardware: " + origin);
        }
        if (!canSign) throw new IllegalStateException("attested key lacks SIGN purpose");

        byte[] bootKey = ASN1OctetString.getInstance(rootOfTrust.getObjectAt(0)).getOctets();
        boolean deviceLocked = ASN1Boolean.getInstance(rootOfTrust.getObjectAt(1)).isTrue();
        int bootStateEnum = ASN1Enumerated.getInstance(rootOfTrust.getObjectAt(2)).intValueExact();
        r.bootState = switch (bootStateEnum) {
            case 0 -> "Verified";
            case 1 -> "SelfSigned";
            case 2 -> "Unverified";
            default -> "Failed";
        };
        r.bootKeySha256Hex = HexFormat.of().formatHex(bootKey);
        if (!deviceLocked) throw new IllegalStateException("bootloader not locked");

        // 5. Verified-boot policy (this is where GrapheneOS is a first-class citizen).
        for (var e : allowlist.getAsJsonArray("verified_boot")) {
            JsonObject o = e.getAsJsonObject();
            if (!o.get("state").getAsString().equals(r.bootState)) continue;
            if (o.has("boot_key_sha256")) {
                JsonArray keys = o.getAsJsonArray("boot_key_sha256");
                boolean hit = false;
                for (var k : keys) hit |= k.getAsString().equalsIgnoreCase(r.bootKeySha256Hex);
                if (!hit && keys.size() > 0) continue;
                if (keys.size() == 0) continue; // SelfSigned with no allowlisted keys = no match
            }
            r.bootPolicyName = o.get("name").getAsString();
        }
        if (r.bootPolicyName == null) {
            throw new IllegalStateException("verified-boot state/key not allowlisted: "
                    + r.bootState + " key=" + r.bootKeySha256Hex);
        }

        // 6. Patch level + key policy.
        int minPatch = allowlist.get("min_patch_level").getAsInt();
        if (r.osPatchLevel < minPatch) {
            throw new IllegalStateException("os patch level " + r.osPatchLevel
                    + " below policy minimum " + minPatch);
        }
        if (allowlist.get("require_user_auth").getAsBoolean() && !r.userAuthRequired) {
            throw new IllegalStateException("key not auth-bound (noAuthRequired set)");
        }

        // 7. Which app generated the key (softwareEnforced attestationApplicationId).
        //    Without this, any app on a genuine device produces an acceptable key.
        if (allowlist.has("attestation_apps")) {
            checkApplicationId(ASN1Sequence.getInstance(att.getObjectAt(6)),
                    allowlist.getAsJsonArray("attestation_apps"), r);
        }
        return r;
    }

    /** AttestationApplicationId ::= SEQUENCE { packageInfos SET OF
     *  AttestationPackageInfo { packageName OCTET STRING, version INTEGER },
     *  signatureDigests SET OF OCTET STRING }. Every package sharing the key's
     *  uid is listed; require exactly one, allowlisted, with a pinned signer
     *  digest when the allowlist entry gives any. */
    static void checkApplicationId(ASN1Sequence swEnforced, JsonArray apps, Result r) {
        ASN1Sequence appId = null;
        for (var el : swEnforced) {
            ASN1TaggedObject t = ASN1TaggedObject.getInstance(el);
            if (t.getTagNo() == TAG_ATTESTATION_APPLICATION_ID) {
                appId = ASN1Sequence.getInstance(
                        ASN1OctetString.getInstance(t.getExplicitBaseObject()).getOctets());
            }
        }
        if (appId == null) throw new IllegalStateException("no attestationApplicationId");
        ASN1Set pkgs = ASN1Set.getInstance(appId.getObjectAt(0));
        if (pkgs.size() != 1) throw new IllegalStateException("key uid shared by " + pkgs.size() + " packages");
        String pkg = new String(ASN1OctetString.getInstance(
                ASN1Sequence.getInstance(pkgs.getObjectAt(0)).getObjectAt(0)).getOctets(),
                java.nio.charset.StandardCharsets.UTF_8);
        java.util.Set<String> signers = new java.util.HashSet<>();
        for (var d : ASN1Set.getInstance(appId.getObjectAt(1))) {
            signers.add(HexFormat.of().formatHex(ASN1OctetString.getInstance(d).getOctets()));
        }
        for (var e : apps) {
            JsonObject o = e.getAsJsonObject();
            if (!o.get("package").getAsString().equals(pkg)) continue;
            JsonArray pinned = o.has("signer_sha256") ? o.getAsJsonArray("signer_sha256") : new JsonArray();
            boolean ok = pinned.isEmpty();
            for (var s : pinned) ok |= signers.contains(s.getAsString().toLowerCase());
            if (ok) { r.appPackage = pkg; return; }
        }
        throw new IllegalStateException("attesting app not allowlisted");
    }

    /** Verifies the device signature over the challenge with the attested key. */
    public static void verifyDeviceSig(X509Certificate leaf, byte[] challenge, byte[] sig)
            throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initVerify(leaf.getPublicKey());
        s.update(challenge);
        if (!s.verify(sig)) throw new IllegalStateException("device signature invalid");
    }

    public static List<X509Certificate> readChain(byte[] pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificates(new ByteArrayInputStream(pem)).stream()
                .map(c -> (X509Certificate) c).toList();
    }

    public static JsonObject readAllowlist(String json) {
        return JsonParser.parseString(json).getAsJsonObject();
    }

    static String sha256Hex(byte[] b) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    private AttestationVerifier() {}
}