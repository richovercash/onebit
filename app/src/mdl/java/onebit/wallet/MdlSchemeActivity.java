// SPDX-License-Identifier: AGPL-3.0-only
package onebit.wallet;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * mDL ingestion via the ISO 18013-7 OpenID4VP custom-scheme flow — the path that
 * gets past the DC API's "unknown origin" gate. We launch a signed `mdoc-openid4vp://`
 * request (RFC 9101 JAR, x509_san_dns client_id) with `response_mode=direct_post.jwt`;
 * the CA Wallet POSTs an encrypted (ECDH-ES/A128GCM JWE) mdoc DeviceResponse back to
 * a localhost `response_uri` we host. We decrypt, verify against the CA IACA trust,
 * and learn exactly one bit. Requests ONLY age_over_18 — no name/DOB/number/etc.
 *
 * Privacy: nothing raw is persisted or logged; only the single over-18 bit.
 *
 * ponytail: passive auth only — we verify the DMV's *issuer* signature over
 * age_over_18 (provenance), not the mdoc *device* signature (holder-binding /
 * anti-replay). The one bit's authenticity comes from the issuer. Add device-auth +
 * SessionTranscript binding if replay resistance is ever needed.
 */
public class MdlSchemeActivity extends Activity {
    static final String TAG = "ONEBIT_MDL";
    static final String NS = "org.iso.18013.5.1";
    static final String CLIENT_ID = "x509_san_dns:onebit.zk";

    private ServerSocket server;
    private ECPrivateKey encPriv;   // ephemeral reader key the wallet encrypts to
    private String reqNonce;        // OID4VP authz-request nonce (SessionTranscript input)
    private String respUri;         // response_uri we host (SessionTranscript input)

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Uri data = getIntent() == null ? null : getIntent().getData();
        if (data != null && "onebitmdl".equals(data.getScheme())) { finish(); return; } // legacy redirect: unused now
        try { start(); } catch (Throwable t) { fail("request", t); finish(); }
        // do NOT finish here — the localhost handler finishes once the wallet responds.
    }

    void start() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair enc = kpg.generateKeyPair();
        encPriv = (ECPrivateKey) enc.getPrivate();

        // Keep the process unfrozen (cached-app freezer) so the socket thread runs
        // while the wallet is foreground.
        startForegroundService(new Intent(this, KeepAliveService.class));

        server = new ServerSocket();
        server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
        int port = server.getLocalPort();
        new Thread(this::serve, "onebit-mdl-cb").start();

        reqNonce = rand16();
        respUri = "http://127.0.0.1:" + port + "/cb";
        String jar = buildJar(reqNonce, (ECPublicKey) enc.getPublic(), respUri);
        Uri u = new Uri.Builder().scheme("mdoc-openid4vp").authority("")
                .appendQueryParameter("client_id", CLIENT_ID)
                .appendQueryParameter("request", jar).build();
        Log.i(TAG, "launching direct_post.jwt request (age_over_18 only) -> " + respUri);
        startActivity(new Intent(Intent.ACTION_VIEW, u).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));

        new Handler(getMainLooper()).postDelayed(this::cleanup, 600_000); // ample time for the interactive consent tap
    }

    /** Signed authorization request (RFC 9101) with response encryption advertised. */
    String buildJar(String nonce, ECPublicKey encPub, String respUri) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();                       // request-signing key
        long now = System.currentTimeMillis();
        org.bouncycastle.asn1.x500.X500Name dn = new org.bouncycastle.asn1.x500.X500Name("CN=onebit-reader");
        org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder cb =
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(dn, BigInteger.valueOf(now),
                        new java.util.Date(now - 86400000L), new java.util.Date(now + 86400000L), dn, kp.getPublic());
        cb.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                new org.bouncycastle.asn1.x509.GeneralNames(
                        new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.dNSName, "onebit.zk")));
        X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .getCertificate(cb.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate())));

        String x5c = Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP);
        String header = "{\"alg\":\"ES256\",\"typ\":\"oauth-authz-req+jwt\",\"x5c\":[\"" + x5c + "\"]}";

        JSONObject pd = new JSONObject("{\"id\":\"onebit-age\",\"input_descriptors\":[{"
                + "\"id\":\"" + NS + ".mDL\",\"format\":{\"mso_mdoc\":{\"alg\":[\"ES256\"]}},"
                + "\"constraints\":{\"limit_disclosure\":\"required\",\"fields\":[{"
                + "\"path\":[\"$['" + NS + "']['age_over_18']\"],\"intent_to_retain\":false}]}}]}");
        JSONObject jwk = new JSONObject().put("kty", "EC").put("crv", "P-256")
                .put("use", "enc").put("alg", "ECDH-ES").put("kid", "reader-enc")
                .put("x", b64u(fixedBE(encPub.getW().getAffineX(), 32)))
                .put("y", b64u(fixedBE(encPub.getW().getAffineY(), 32)));
        JSONObject clientMeta = new JSONObject()
                .put("jwks", new JSONObject().put("keys", new JSONArray().put(jwk)))
                .put("authorization_encrypted_response_alg", "ECDH-ES")
                .put("authorization_encrypted_response_enc", "A256GCM") // SpruceID draft18 rejects A128GCM
                .put("encrypted_response_enc_values_supported", new JSONArray().put("A256GCM"))
                .put("vp_formats", new JSONObject().put("mso_mdoc", new JSONObject().put("alg", new JSONArray().put("ES256"))));
        JSONObject payload = new JSONObject()
                .put("response_type", "vp_token").put("client_id", CLIENT_ID)
                .put("response_mode", "direct_post.jwt").put("response_uri", respUri)
                .put("nonce", nonce).put("presentation_definition", pd)
                .put("client_metadata", clientMeta)
                .put("iat", now / 1000).put("exp", now / 1000 + 300);

        String si = b64u(header.getBytes("UTF-8")) + "." + b64u(payload.toString().getBytes("UTF-8"));
        java.security.Signature s = java.security.Signature.getInstance("SHA256withECDSA");
        s.initSign(kp.getPrivate());
        s.update(si.getBytes("UTF-8"));
        return si + "." + b64u(joseSig(s.sign()));
    }

    /** Accept one POST from the wallet, decrypt + verify, learn the bit. */
    void serve() {
        try (Socket s = server.accept()) {
            InputStream in = s.getInputStream();
            byte[] body = readHttpBody(in);
            String form = new String(body, "UTF-8");
            String jwe = formParam(form, "response");
            if (jwe == null) jwe = form.trim();          // some wallets POST the JWE raw
            onebit.core.Mdl.MdlData d = process(jwe);
            boolean over18 = d.ageOver(18);
            OutputStream os = s.getOutputStream();
            os.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").getBytes("UTF-8"));
            os.flush();
            String note = over18 ? (enrollBool(d, 18) ? "  (enrolled ✓)" : "  (enroll skipped)") : "";
            Log.i(TAG, "CA mDL VERIFIED via direct_post.jwt — age_over_18=" + over18 + note);
            final String fnote = note;
            runOnUiThread(() -> Toast.makeText(this, "CA mDL verified ✓ over-18=" + over18 + fnote, Toast.LENGTH_LONG).show());
        } catch (Throwable t) {
            Log.w(TAG, "serve: " + t);
            runOnUiThread(() -> Toast.makeText(this, "mDL response failed: " + t.getClass().getSimpleName(), Toast.LENGTH_LONG).show());
        } finally { cleanup(); runOnUiThread(this::finish); }
    }

    /** JWE compact -> mdoc DeviceResponse -> issuer-verified MdlData. */
    onebit.core.Mdl.MdlData process(String jwe) throws Exception {
        String[] p = jwe.split("\\.");
        if (p.length != 5) throw new IllegalArgumentException("not a compact JWE (" + p.length + " parts)");
        JSONObject h = new JSONObject(new String(ub64(p[0]), "UTF-8"));
        String enc = h.getString("enc");                 // A128GCM / A256GCM
        int bits = enc.startsWith("A256") ? 256 : 128;
        JSONObject epk = h.getJSONObject("epk");
        ECPublicKey epkPub = ecPub(epk.getString("x"), epk.getString("y"));
        byte[] apu = h.has("apu") ? ub64(h.getString("apu")) : new byte[0];
        byte[] apv = h.has("apv") ? ub64(h.getString("apv")) : new byte[0];

        byte[] cek = onebit.core.Jwe.derive(encPriv, epkPub, bits, enc, apu, apv);
        byte[] pt = onebit.core.Jwe.gcmDecrypt(cek, ub64(p[2]), ub64(p[3]), ub64(p[4]), p[0].getBytes("US-ASCII"));

        JSONObject resp = new JSONObject(new String(pt, "UTF-8"));
        String tok = vpToken(resp.opt("vp_token"));
        if (tok == null) throw new IllegalStateException("no vp_token in response");
        byte[] dr = ub64(tok);                            // DeviceResponse CBOR
        java.util.List<X509Certificate> chain = onebit.core.Mdl.x5chain(dr);
        X509Certificate ds = chain.get(0);
        Log.i(TAG, "mdoc DS: " + ds.getSubjectX500Principal() + " | iss " + ds.getIssuerX500Principal());

        // CA does not publish the ISO 18013-5 IACA Root (VICAL-only). Bootstrap its
        // public key by cross-validating the live DS against the dmv.ca.gov-published
        // VC-Signer we bundle: the recovered key that signs BOTH is genuinely CA's root.
        // Demo trust anchor, pending an AAMVA VICAL assertion.
        final java.security.PublicKey root = onebit.core.Mdl.crossValidatedRootKey(ds, trust());
        onebit.core.Mdl.Anchor anchor = c -> {
            try { c.verify(root); return c.getIssuerX500Principal().equals(ds.getIssuerX500Principal()); }
            catch (Exception e) { return false; }
        };
        // Holder-binding: verify the mdoc DeviceSignature over the ISO 18013-7 OID4VP
        // SessionTranscript for THIS exchange (binds the response to our nonce +
        // response_uri, defeating replay of a captured issuerSigned blob). mdocGeneratedNonce
        // travels in the JWE apu header. Fails closed if deviceAuth is missing/invalid.
        byte[] sessionTranscript = oid4vpSessionTranscript(apu);
        onebit.core.Mdl.MdlData d = onebit.core.Mdl.verifyDeviceResponse(dr, anchor, sessionTranscript);
        Log.i(TAG, "IACA root bootstrapped via cross-validation (pending VICAL); deviceAuth holder-binding OK");
        return d;
    }

    /** ISO 18013-7 Annex B OID4VPHandover SessionTranscript:
     *  [ null, null, [ SHA256(cbor[client_id, mdocNonce]), SHA256(cbor[response_uri, mdocNonce]), nonce ] ].
     *  mdocGeneratedNonce is the JWE apu (base64url text the wallet supplied). This is the
     *  one wallet-profile-sensitive spot — if a wallet uses a different handover encoding,
     *  deviceAuth fails closed and this builder is what to adjust. */
    byte[] oid4vpSessionTranscript(byte[] apu) throws Exception {
        String mdocNonce = new String(apu, "US-ASCII");
        java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
        byte[] clientIdHash = sha.digest(onebit.core.Cbor.array(
                onebit.core.Cbor.tstr(CLIENT_ID), onebit.core.Cbor.tstr(mdocNonce)));
        byte[] respUriHash = sha.digest(onebit.core.Cbor.array(
                onebit.core.Cbor.tstr(respUri), onebit.core.Cbor.tstr(mdocNonce)));
        byte[] handover = onebit.core.Cbor.array(
                onebit.core.Cbor.bstr(clientIdHash), onebit.core.Cbor.bstr(respUriHash),
                onebit.core.Cbor.tstr(reqNonce));
        return onebit.core.Cbor.array(onebit.core.Cbor.nul(), onebit.core.Cbor.nul(), handover);
    }

    /** Amortized Tier-A enrollment from the verified mDL: commit the disclosed age
     *  BOOLEAN (not a dob — we never requested one, per the PII rule) as
     *  C = Poseidon2([over, threshold, doc_hash, k, salt]) via commit_fields, and
     *  SE-seal the 6 fields present_bool reopens. After this, age answers come from
     *  present_bool (~0.8s, offline) — no wallet round-trip or FGS/socket needed again.
     *  Returns true iff a credential was sealed. */
    boolean enrollBool(onebit.core.Mdl.MdlData d, int threshold) {
        try {
            java.io.File g1 = new java.io.File(getExternalFilesDir(null), "g1_big.dat");
            if (!g1.exists()) { Log.w(TAG, "enrollBool skipped: SRS g1_big.dat missing"); return false; }
            java.math.BigInteger P = new java.math.BigInteger(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617");
            java.math.BigInteger docHash = new java.math.BigInteger(1,
                    java.security.MessageDigest.getInstance("SHA-256").digest(d.msoBytes)).mod(P);
            java.math.BigInteger k = new java.math.BigInteger(250, new java.security.SecureRandom());
            java.math.BigInteger salt = new java.math.BigInteger(250, new java.security.SecureRandom());
            String w = "1\n" + threshold + "\n" + docHash + "\n" + k + "\n" + salt;   // over=1
            byte[] proof = NativeProver.prove(readZk("zk/commit_fields.json"), w, g1.getAbsolutePath(), false);
            String c = new java.math.BigInteger(1, java.util.Arrays.copyOfRange(proof, 4, 36)).toString();
            String blob = "1\n" + threshold + "\n" + docHash + "\n" + k + "\n" + salt + "\n" + c;
            Seal.writeFile(new java.io.File(getFilesDir(), "acred.bin").toPath(), blob.getBytes("UTF-8"));
            java.nio.file.Files.write(new java.io.File(getFilesDir(), "credtype.txt").toPath(), "bool".getBytes("UTF-8"));
            Log.i(TAG, "mDL amortized credential sealed (bool, threshold=" + threshold + ")");
            return true;
        } catch (Throwable t) { Log.w(TAG, "enrollBool: " + t); return false; }
    }

    String readZk(String path) throws Exception {
        try (InputStream in = getAssets().open(path)) {
            java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192]; int n;
            while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
            return o.toString("UTF-8");
        }
    }

    static String vpToken(Object vp) throws Exception {
        if (vp instanceof String) return (String) vp;
        if (vp instanceof JSONArray && ((JSONArray) vp).length() > 0) return ((JSONArray) vp).getString(0);
        if (vp instanceof JSONObject) {
            JSONObject o = (JSONObject) vp;
            java.util.Iterator<String> it = o.keys();
            if (it.hasNext()) { Object v = o.get(it.next()); return v instanceof JSONArray ? ((JSONArray) v).getString(0) : v.toString(); }
        }
        return null;
    }

    // ---- helpers ----

    /** Read an HTTP request: skip headers, honor Content-Length for the body. */
    static byte[] readHttpBody(InputStream in) throws Exception {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int b, hits = 0;
        while ((b = in.read()) != -1) {                  // stop after CRLFCRLF
            head.write(b);
            hits = (b == '\r' || b == '\n') ? hits + 1 : 0;
            if (hits == 4) break;
        }
        int len = 0;
        for (String line : new String(head.toByteArray(), "UTF-8").split("\r\n")) {
            int c = line.indexOf(':');
            if (c > 0 && line.substring(0, c).trim().equalsIgnoreCase("Content-Length"))
                len = Integer.parseInt(line.substring(c + 1).trim());
        }
        // Bound the attacker-controlled length before allocating. mDL response JWEs are
        // tens of KB; cap at 512KB so a malicious local app can't force a huge allocation.
        if (len < 0 || len > 512 * 1024)
            throw new IllegalStateException("Content-Length out of range: " + len);
        byte[] body = new byte[len];
        int off = 0;
        while (off < len) { int r = in.read(body, off, len - off); if (r < 0) break; off += r; }
        return body;
    }

    static String formParam(String s, String key) {
        for (String kv : s.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0 && kv.substring(0, i).equals(key)) return Uri.decode(kv.substring(i + 1));
        }
        return null;
    }

    static ECPublicKey ecPub(String x, String y) throws Exception {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec sp = ap.getParameterSpec(ECParameterSpec.class);
        ECPoint pt = new ECPoint(new BigInteger(1, ub64(x)), new BigInteger(1, ub64(y)));
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(pt, sp));
    }

    static byte[] fixedBE(BigInteger v, int n) {
        byte[] b = v.toByteArray();
        if (b.length == n) return b;
        byte[] out = new byte[n];
        if (b.length > n) System.arraycopy(b, b.length - n, out, 0, n);          // strip sign byte
        else System.arraycopy(b, 0, out, n - b.length, b.length);                // left-pad
        return out;
    }

    static String rand16() {
        byte[] n = new byte[16];
        new java.security.SecureRandom().nextBytes(n);
        return b64u(n);
    }

    static byte[] joseSig(byte[] der) {
        org.bouncycastle.asn1.ASN1Sequence seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(der);
        BigInteger r = ((org.bouncycastle.asn1.ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger sg = ((org.bouncycastle.asn1.ASN1Integer) seq.getObjectAt(1)).getValue();
        byte[] out = new byte[64];
        System.arraycopy(fixedBE(r, 32), 0, out, 0, 32);
        System.arraycopy(fixedBE(sg, 32), 0, out, 32, 32);
        return out;
    }

    static String b64u(byte[] b) { return Base64.encodeToString(b, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING); }
    static byte[] ub64(String s) { return Base64.decode(s, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING); }

    List<X509Certificate> trust() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> t = new ArrayList<>();
        for (String f : new String[]{"mdl/ca_iaca_prod.der", "mdl/ca_iaca_test.der"}) {
            try (InputStream in = getAssets().open(f)) { t.add((X509Certificate) cf.generateCertificate(in)); }
        }
        return t;
    }

    synchronized void cleanup() {
        try { if (server != null) { server.close(); server = null; } } catch (Throwable ignored) {}
        try { stopService(new Intent(this, KeepAliveService.class)); } catch (Throwable ignored) {}
    }

    void fail(String where, Throwable t) {
        Log.w(TAG, where + ": " + t);
        runOnUiThread(() -> Toast.makeText(this, "mDL " + where + " failed: " + t.getClass().getSimpleName(), Toast.LENGTH_LONG).show());
    }
}