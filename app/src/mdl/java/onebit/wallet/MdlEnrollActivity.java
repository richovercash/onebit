// SPDX-License-Identifier: AGPL-3.0-only
package onebit.wallet;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import androidx.credentials.Credential;
import androidx.credentials.CredentialManager;
import androidx.credentials.CredentialManagerCallback;
import androidx.credentials.DigitalCredential;
import androidx.credentials.GetCredentialRequest;
import androidx.credentials.GetCredentialResponse;
import androidx.credentials.GetDigitalCredentialOption;
import androidx.credentials.exceptions.GetCredentialException;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;

/**
 * mDL ingestion via the Android Digital Credentials API (verifier side). Requests
 * ONLY the issuer-signed age booleans (age_over_18 / age_over_21) — never name,
 * address, document number, birth date, or portrait — so no PII is ever
 * requested. The returned mdoc DeviceResponse is verified by {@link onebit.core.Mdl}
 * against the bundled CA IACA trust, and we learn exactly one bit.
 *
 * Privacy: nothing raw is persisted or logged. We log only structure + the single
 * over-18 bit (the product's whole output), never a disclosed value.
 */
public class MdlEnrollActivity extends Activity {
    static final String TAG = "ONEBIT_MDL";
    static final String NS = "org.iso.18013.5.1";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        try { requestMdl(); } catch (Throwable t) { fail("request build", t); }
    }

    void requestMdl() {
        byte[] n = new byte[16];
        new java.security.SecureRandom().nextBytes(n);
        String nonce = Base64.encodeToString(n, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        // OID4VP request over the DC API — age booleans only, no PII.
        // client_id + expected_origins: the DC-API/OID4VP way a verifier declares
        // its origin so the wallet can bind + accept it (the "unknown origin" gate).
        String origin = "https://onebit.zk";
        String req = "{\"requests\":[{\"protocol\":\"openid4vp-v1-unsigned\",\"data\":{"
                + "\"response_type\":\"vp_token\",\"response_mode\":\"dc_api\",\"nonce\":\"" + nonce + "\","
                + "\"client_id\":\"web-origin:" + origin + "\",\"expected_origins\":[\"" + origin + "\"],"
                + "\"dcql_query\":{\"credentials\":[{\"id\":\"mdl\",\"format\":\"mso_mdoc\","
                + "\"meta\":{\"doctype_value\":\"org.iso.18013.5.1.mDL\"},"
                + "\"claims\":[{\"path\":[\"" + NS + "\",\"age_over_18\"]},"
                + "{\"path\":[\"" + NS + "\",\"age_over_21\"]}]}]}}}]}";

        CredentialManager cm = CredentialManager.create(this);
        GetCredentialRequest gr = new GetCredentialRequest(
                List.of(new GetDigitalCredentialOption(req)));
        Log.i(TAG, "requesting mDL age booleans via DC API…");
        cm.getCredentialAsync(this, gr, null, Runnable::run,
                new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                    @Override public void onResult(GetCredentialResponse r) { handle(r); }
                    @Override public void onError(GetCredentialException e) { fail("DC API", e); }
                });
    }

    void handle(GetCredentialResponse r) {
        try {
            Credential c = r.getCredential();
            if (!(c instanceof DigitalCredential)) { toast("unexpected credential: " + c.getType()); finish(); return; }
            byte[] dr = extractDeviceResponse(((DigitalCredential) c).getCredentialJson());
            if (dr == null) { toast("response present but no parseable mdoc (maybe encrypted) — see log"); finish(); return; }
            // Display/probe only: this DC-API path never enrolls (see handle() — it just
            // toasts). Issuer provenance is enough to show the bit; it deliberately does NOT
            // assert holder-binding. Any enrolling path must use the deviceAuth overload.
            onebit.core.Mdl.MdlData d = onebit.core.Mdl.verifyIssuerAuth(dr, trust());
            boolean over18 = d.ageOver(18);
            Log.i(TAG, "mDL VERIFIED (issuer only, no holder-binding) — age_over_18=" + over18
                    + " (DS issuer=" + d.ds.getIssuerX500Principal() + ")");
            toast("CA mDL verified ✓  over-18 = " + over18);
            finish();
        } catch (Throwable t) { fail("verify", t); }
    }

    /** OID4VP response JSON -> the mdoc DeviceResponse bytes. Handles the vp_token
     *  as an object keyed by credential id or a bare string. Logs (structure only)
     *  and returns null if it looks encrypted (JWE) — that tells us decryption is
     *  needed without exposing anything. */
    byte[] extractDeviceResponse(String json) throws Exception {
        JSONObject o = new JSONObject(json);
        Object vp = o.opt("vp_token");
        String tok = null;
        if (vp instanceof JSONObject) {
            JSONObject m = (JSONObject) vp;
            java.util.Iterator<String> it = m.keys();
            if (it.hasNext()) tok = m.getString(it.next());
        } else if (vp instanceof String) {
            tok = (String) vp;
        }
        if (tok == null) { Log.w(TAG, "no vp_token; response keys=" + o.keys().hasNext()); return null; }
        if (tok.split("\\.").length >= 3) { Log.w(TAG, "vp_token looks like a JWE (encrypted) — decryption path needed"); return null; }
        return Base64.decode(tok, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    List<X509Certificate> trust() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> t = new ArrayList<>();
        // The DMV UAT (test) root ships only in debug builds (src/mdlDebug): UAT
        // mdocs carry tester-chosen attributes, so release trusts prod alone.
        List<String> files = new ArrayList<>();
        files.add("mdl/ca_iaca_prod.der");
        if (java.util.Arrays.asList(getAssets().list("mdl")).contains("ca_iaca_test.der")) {
            files.add("mdl/ca_iaca_test.der");
        }
        for (String f : files) {
            try (java.io.InputStream in = getAssets().open(f)) {
                t.add((X509Certificate) cf.generateCertificate(in));
            }
        }
        return t;
    }

    void toast(String m) { runOnUiThread(() -> Toast.makeText(this, m, Toast.LENGTH_LONG).show()); }
    void fail(String where, Throwable t) {
        Log.w(TAG, where + ": " + t);
        toast("mDL " + where + " failed: " + t.getClass().getSimpleName());
        finish();
    }
}