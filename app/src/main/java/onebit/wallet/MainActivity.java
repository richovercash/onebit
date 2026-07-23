package onebit.wallet;

import android.app.Activity;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.text.InputType;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.IsoDepCardService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.BACKey;
import org.jmrtd.PassportService;

import onebit.core.Mrz;
import onebit.core.PassiveAuth;

/**
 * T1 harness: MRZ fields in, NFC tap, BAC, read DG1+SOD, local Passive
 * Authentication against the bundled master list. No network path exists
 * (no INTERNET permission in the manifest).
 */
public class MainActivity extends Activity {

    private EditText docNo, dob, expiry;
    private TextView status;
    private NfcAdapter nfc;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Android ships a stripped "BC"; replace it with the real one so
        // jmrtd/PA get full algorithm coverage.
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        if (getActionBar() != null) getActionBar().hide();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        // targetSdk 35 forces edge-to-edge: keep the form out from under the
        // status bar / keyboard by padding with the live insets.
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            android.graphics.Insets in = insets.getInsets(
                    android.view.WindowInsets.Type.systemBars()
                            | android.view.WindowInsets.Type.ime());
            v.setPadding(pad + in.left, pad + in.top, pad + in.right, pad + in.bottom);
            return android.view.WindowInsets.CONSUMED;
        });

        docNo = field(root, "Document number");
        LinearLayout dates = new LinearLayout(this);
        dates.setOrientation(LinearLayout.HORIZONTAL);
        dob = field(dates, "Birth YYMMDD");
        expiry = field(dates, "Expiry YYMMDD");
        dob.setInputType(InputType.TYPE_CLASS_NUMBER);
        expiry.setInputType(InputType.TYPE_CLASS_NUMBER);
        expiry.setImeOptions(android.view.inputmethod.EditorInfo.IME_ACTION_DONE);
        root.addView(dates);
        android.widget.Button attest = new android.widget.Button(this);
        attest.setText("Attest device key (T3 demo)");
        attest.setOnClickListener(v -> Attest.run(this, "demo-verifier-01", this::say));
        root.addView(attest);

        android.widget.Button nativeBtn = new android.widget.Button(this);
        nativeBtn.setText("Native prove (slim circuit, JNI)");
        nativeBtn.setOnClickListener(v -> nativeProveTest("zk/mono_slim.json", "zk/wit_slim.txt", "slim"));
        root.addView(nativeBtn);

        // P1.0 spike: native (multi-threaded) recursive Circuit P v1 prove-time.
        // The WASM WebView bench (below) fell back to single-thread (~93s on P6P);
        // this is the number that actually matters for presentations.
        android.widget.Button pBtn = new android.widget.Button(this);
        pBtn.setText("Native prove (Circuit P v1 recursion, 775k)");
        pBtn.setOnClickListener(v -> nativeProveTest("zk/circuit_p.json", "zk/wit_p.txt", "recursion-775k"));
        root.addView(pBtn);

        addBench(root, "Benchmark: recursion (Circuit P v1, 775k)",
                "c=circuit_p_v1.json&i=bench_p_inputs.json&l=recursion-775k");
        addBench(root, "Benchmark: monolithic (Option A, 177k)",
                "c=circuit_mono.json&i=mono_inputs.json&l=monolithic-177k");

        status = new TextView(this);
        status.setTextIsSelectable(true);
        status.setText("Fill MRZ fields, then hold document to the phone.");
        ScrollView scroll = new ScrollView(this);
        scroll.addView(status);
        root.addView(scroll);
        setContentView(root);

        SharedPreferences p = getPreferences(MODE_PRIVATE);
        docNo.setText(p.getString("doc", ""));
        dob.setText(p.getString("dob", ""));
        expiry.setText(p.getString("exp", ""));

        android.text.TextWatcher watcher = new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            public void onTextChanged(CharSequence s, int a, int b, int c) {}
            public void afterTextChanged(android.text.Editable s) { say(readiness()); }
        };
        docNo.addTextChangedListener(watcher);
        dob.addTextChangedListener(watcher);
        expiry.addTextChangedListener(watcher);
        say(readiness());

        nfc = NfcAdapter.getDefaultAdapter(this);
        if (nfc == null) status.setText("No NFC on this device.");

        handleDeepLink(getIntent());
    }

    @Override
    protected void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        handleDeepLink(intent);
    }

    /** JNI native-proving test: loads libonebitprover.so and proves the slim
     *  circuit. g1.dat must be pushed to the app files dir first. */
    private void nativeProveTest(String circuitAsset, String witAsset, String label) {
        final String TAG = "ONEBIT_NATIVE";
        if (NativeProver.loadError != null) {
            android.util.Log.e(TAG, "LOAD FAILED", NativeProver.loadError);
            say("Native lib FAILED to load: " + NativeProver.loadError);
            return;
        }
        android.util.Log.i(TAG, "lib loaded OK");
        say("Native lib loaded OK. Proving " + label + " (native, multi-threaded)…");
        new Thread(() -> {
            android.os.PowerManager pm = getSystemService(android.os.PowerManager.class);
            android.os.PowerManager.WakeLock wl = pm.newWakeLock(
                    android.os.PowerManager.PARTIAL_WAKE_LOCK, "onebit:prove");
            try {
                // Keep CPU at full clocks during proving (screen may be off).
                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_DISPLAY);
                wl.acquire(600_000);
                String circuit = readAsset(circuitAsset);
                String witness = readAsset(witAsset);
                java.io.File g1 = new java.io.File(getExternalFilesDir(null), "g1_big.dat");
                if (!g1.exists()) { say("missing SRS g1_big.dat"); return; }
                long t0 = System.currentTimeMillis();
                byte[] proof = NativeProver.prove(circuit, witness, g1.getAbsolutePath(), false);
                long ms = System.currentTimeMillis() - t0;
                android.util.Log.i(TAG, "PROVE OK [" + label + "] " + ms + " ms, proof " + proof.length + " B");
                say("NATIVE PROVE [" + label + "] OK in " + ms + " ms (proof " + proof.length + " B)");
            } catch (Throwable t) {
                android.util.Log.e(TAG, "PROVE FAIL", t);
                say("Native prove [" + label + "] FAIL: " + t);
            } finally {
                if (wl.isHeld()) wl.release();
            }
        }).start();
    }

    private String readAsset(String path) throws Exception {
        try (java.io.InputStream in = getAssets().open(path)) {
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private final StringBuilder benchLog = new StringBuilder();

    private void addBench(LinearLayout root, String label, String query) {
        android.widget.Button b = new android.widget.Button(this);
        b.setText(label);
        b.setOnClickListener(v -> {
            benchLog.setLength(0);
            say("Loading prover for " + label + "…");
            new ZkProver(this, new ZkProver.Callback() {
                public void onReady(String t) { benchLog.append("diag: ").append(t).append('\n'); say(benchLog.toString()); }
                public void onProgress(String l) { benchLog.append(l).append('\n'); say(benchLog.toString()); }
                public void onProof(String r) { benchLog.append("RESULT ").append(r); say(benchLog.toString()); }
                public void onError(String m) { say(benchLog + "\nFAIL: " + m); }
            }, "https://onebit.zk/zk/bench.html?" + query);
        });
        root.addView(b);
    }

    /** One-time enrollment proof: CSCA (in master list) signed the DSC. Routes
     *  to the enroll variant for the CSCA's algorithm (RSA≤4096 / RSA-6144 /
     *  brainpoolP256r1 / secp384r1). Persists enrollproof.bin + the algorithm
     *  tag; presentation sends both, the verifier checks the matching root. */
    private void proveEnroll(byte[] dg1, byte[] sod,
                             java.util.List<java.security.cert.X509Certificate> masterList,
                             PassiveAuth.MrzData d) {
        try {
            onebit.core.Witness.EnrollPlan plan = onebit.core.Witness.enrollRouted(
                    dg1, sod, masterList, alg -> {
                        try { return readAsset("zk/cscatree_" + alg + ".json"); }
                        catch (Exception e) { throw new RuntimeException(e); }
                    });
            if (plan == null) { say("Enrolled (DSC OK). CSCA algorithm has no enroll circuit yet (e.g. secp256r1 / brainpoolP384r1)."); return; }
            java.io.File g1 = new java.io.File(getExternalFilesDir(null), "g1_big.dat");
            if (!g1.exists()) { say("Enrolled. (SRS missing for enroll proof.)"); return; }
            android.os.PowerManager pm = getSystemService(android.os.PowerManager.class);
            android.os.PowerManager.WakeLock wl = pm.newWakeLock(
                    android.os.PowerManager.PARTIAL_WAKE_LOCK, "onebit:enroll");
            wl.acquire(600_000);
            try {
                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_DISPLAY);
                String circuit = readAsset(plan.circuitAsset);
                long e0 = System.currentTimeMillis();
                byte[] proof = NativeProver.prove(circuit, String.join("\n", plan.witness), g1.getAbsolutePath(), false);
                Seal.writeFile(new java.io.File(getFilesDir(), "enrollproof.bin").toPath(), proof);
                java.nio.file.Files.write(new java.io.File(getFilesDir(), "enrollalg.txt").toPath(), plan.alg.getBytes());
                say("ENROLLED (" + plan.alg + ") — CSCA→DSC proven in " + (System.currentTimeMillis() - e0) + " ms.\n"
                        + "DSC: " + d.dscInfo + " · full chain ready.");
            } finally { if (wl.isHeld()) wl.release(); }
        } catch (Throwable ex) {
            android.util.Log.w("ONEBIT_ENROLL", "enroll proof: " + ex);
            say("Enrolled (DSC→SOD ready). Enroll proof skipped: " + ex);
        }
    }

    /** Amortized Tier A enrollment: run the `commit` circuit to compute
     *  (C, doc_hash) exactly as Circuit E does, then SE-seal the 6 credential
     *  fields (dob, expiry, doc_hash, k, salt, C) that present_amortized reopens.
     *  One-time; provenance is carried by passive auth (already verified) +
     *  attestation, so no per-presentation recursion. */
    private void enrollAmortized(byte[] dg1, onebit.core.Witness.Doc wd,
                                 PassiveAuth.MrzData d, java.time.LocalDate t) {
        try {
            java.io.File g1 = new java.io.File(getExternalFilesDir(null), "g1_big.dat");
            if (!g1.exists()) { say("Amortized enroll skipped (SRS missing)."); return; }
            java.time.LocalDate dob = Mrz.resolve(d.dateOfBirth, t);
            java.time.LocalDate exp = Mrz.resolve(d.dateOfExpiry, t);
            int dobI = dob.getYear() * 10000 + dob.getMonthValue() * 100 + dob.getDayOfMonth();
            int expI = exp.getYear() * 10000 + exp.getMonthValue() * 100 + exp.getDayOfMonth();
            int enrollDate = t.getYear() * 10000 + t.getMonthValue() * 100 + t.getDayOfMonth();
            java.math.BigInteger k = new java.math.BigInteger(250, new java.security.SecureRandom());
            java.math.BigInteger salt = new java.math.BigInteger(250, new java.security.SecureRandom());

            // commit witness: dg1[93], econtent[1200], k, salt, enroll_date.
            StringBuilder w = new StringBuilder();
            for (byte b : dg1) w.append(b & 0xff).append('\n');
            byte[] econ = new byte[1200];
            System.arraycopy(wd.eContent, 0, econ, 0, Math.min(wd.eContent.length, 1200));
            for (byte b : econ) w.append(b & 0xff).append('\n');
            w.append(k).append('\n').append(salt).append('\n').append(enrollDate);

            byte[] proof = NativeProver.prove(readAsset("zk/commit.json"), w.toString(),
                    g1.getAbsolutePath(), false);
            String cField = pubField(proof, 0);   // C
            String docHash = pubField(proof, 1);   // doc_hash
            String blob = dobI + "\n" + expI + "\n" + docHash + "\n" + k + "\n" + salt + "\n" + cField;
            Seal.writeFile(new java.io.File(getFilesDir(), "acred.bin").toPath(), blob.getBytes());
            say("Amortized credential enrolled — presentations now ~0.8s.");
        } catch (Throwable ex) {
            android.util.Log.w("ONEBIT_ACRED", "amortized enroll: " + ex);
            say("Amortized enroll skipped: " + ex);
        }
    }

    /** Read public input #idx (decimal) from a noir-rs proof
     *  [uint32 num_public][pub][proof]. */
    static String pubField(byte[] proof, int idx) {
        int off = 4 + idx * 32;
        return new java.math.BigInteger(1,
                java.util.Arrays.copyOfRange(proof, off, off + 32)).toString();
    }

    /** Persist credential attributes (SPEC §3.1.5). The nullifier key `k` is
     *  SE-wrapped (P1.5) — it's the secret behind N; a lifted plaintext `k`
     *  would let a custom prover mint arbitrary nullifiers (self-review F2). */
    private void enroll(PassiveAuth.MrzData d, java.time.LocalDate t) throws Exception {
        java.math.BigInteger k = new java.math.BigInteger(250, new java.security.SecureRandom());
        java.time.LocalDate dob = Mrz.resolve(d.dateOfBirth, t);
        java.time.LocalDate exp = Mrz.resolve(d.dateOfExpiry, t);
        String kSealed = android.util.Base64.encodeToString(
                Seal.wrap(k.toString().getBytes()), android.util.Base64.NO_WRAP);
        getSharedPreferences("cred", MODE_PRIVATE).edit()
                .putInt("dob", dob.getYear() * 10000 + dob.getMonthValue() * 100 + dob.getDayOfMonth())
                .putInt("exp", exp.getYear() * 10000 + exp.getMonthValue() * 100 + exp.getDayOfMonth())
                .putString("k", kSealed)
                .apply();
    }

    private void handleDeepLink(android.content.Intent intent) {
        android.net.Uri u = intent == null ? null : intent.getData();
        if (u == null || !"onebit".equals(u.getScheme())) return;
        // P1.0 spike: adb-triggerable native recursion bench (no UI tap needed).
        //   adb shell am start -a android.intent.action.VIEW -d onebit://benchp
        // Read the result: adb logcat -s ONEBIT_NATIVE  ->  PROVE OK [recursion-775k]
        if ("benchp".equals(u.getHost())) {
            nativeProveTest("zk/circuit_p.json", "zk/wit_p.txt", "recursion-775k");
            return;
        }
        String c = u.getQueryParameter("c");
        if (c == null) { say("Deep link missing challenge."); return; }
        String json = new String(android.util.Base64.decode(c,
                android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING),
                java.nio.charset.StandardCharsets.UTF_8);
        new Present(this, this::say).start(json);
    }

    /** null-free readiness message; "Ready" only when BAC inputs are usable. */
    private String readiness() {
        if (docNo.getText().toString().trim().isEmpty()) return "Enter the document number.";
        String err = dateError("Date of birth", dob.getText().toString().trim());
        if (err == null) err = dateError("Expiry", expiry.getText().toString().trim());
        if (err != null) return err;
        return "Ready — hold the document's photo page against the back of the phone.";
    }

    private static String dateError(String label, String v) {
        if (!v.matches("\\d{6}")) return label + ": need 6 digits, YYMMDD (as printed in the MRZ).";
        try {
            Mrz.resolve(v, LocalDate.now());
            return null;
        } catch (RuntimeException e) {
            return label + ": " + v + " is not a real date. MRZ order is YYMMDD, not DDMMYY.";
        }
    }

    private EditText field(LinearLayout parent, String hint) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setSingleLine(true);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS);
        e.setImeOptions(android.view.inputmethod.EditorInfo.IME_ACTION_NEXT
                | android.view.inputmethod.EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        if (parent.getOrientation() == LinearLayout.VERTICAL) {
            lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        }
        parent.addView(e, lp);
        return e;
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfc != null) {
            nfc.enableReaderMode(this, this::onTag,
                    NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B
                            | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfc != null) nfc.disableReaderMode(this);
    }

    private void onTag(Tag tag) {
        String ready = readiness();
        if (!ready.startsWith("Ready")) {
            say("Tag seen, but: " + ready);
            return;
        }
        String doc = docNo.getText().toString().trim();
        String birth = dob.getText().toString().trim();
        String exp = expiry.getText().toString().trim();
        getPreferences(MODE_PRIVATE).edit()
                .putString("doc", doc).putString("dob", birth).putString("exp", exp).apply();
        say("Tag detected, reading chip…");
        new Thread(() -> {
            try {
                IsoDep isoDep = IsoDep.get(tag);
                isoDep.setTimeout(15000);
                CardService cs = new IsoDepCardService(isoDep);
                PassportService ps = new PassportService(cs,
                        PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                        PassportService.DEFAULT_MAX_BLOCKSIZE, false, false);
                ps.open();
                BACKey bacKey = new BACKey(doc, birth, exp);
                // PACE first (modern documents often disable BAC), BAC fallback.
                boolean paceOk = false;
                try {
                    org.jmrtd.lds.CardAccessFile caf = new org.jmrtd.lds.CardAccessFile(
                            ps.getInputStream(PassportService.EF_CARD_ACCESS));
                    for (org.jmrtd.lds.SecurityInfo si : caf.getSecurityInfos()) {
                        if (si instanceof org.jmrtd.lds.PACEInfo) {
                            org.jmrtd.lds.PACEInfo pi = (org.jmrtd.lds.PACEInfo) si;
                            say("PACE (" + pi.getObjectIdentifier() + ")…");
                            ps.doPACE(org.jmrtd.PACEKeySpec.createMRZKey(bacKey),
                                    pi.getObjectIdentifier(),
                                    org.jmrtd.lds.PACEInfo.toParameterSpec(pi.getParameterId()),
                                    pi.getParameterId());
                            paceOk = true;
                            break;
                        }
                    }
                } catch (Exception e) {
                    say("PACE unavailable (" + e.getMessage() + "), trying BAC…");
                }
                ps.sendSelectApplet(paceOk);
                if (!paceOk) ps.doBAC(bacKey);
                say("Access established, reading DG1 + SOD…");
                byte[] dg1 = readAll(ps.getInputStream(PassportService.EF_DG1));
                byte[] sod = readAll(ps.getInputStream(PassportService.EF_SOD));
                say("Read OK (DG1 " + dg1.length + " B, SOD " + sod.length
                        + " B). Running Passive Authentication…");

                List<X509Certificate> masterList = loadMasterList();
                if (masterList.isEmpty()) {
                    say("FAIL (closed): master list is empty — drop CSCA certs in assets/masterlist/.");
                    return;
                }
                PassiveAuth.MrzData d = PassiveAuth.verify(dg1, sod, masterList);
                LocalDate t = LocalDate.now();
                enroll(d, t);
                try {
                    onebit.core.Witness.Doc wd = onebit.core.Witness.extract(dg1, sod);
                    android.util.Log.i("ONEBIT_COVERAGE", "sizes: eContent=" + wd.eContent.length
                            + " signedAttrs=" + wd.signedAttrs.length + " modBits=" + wd.modulus.bitLength());
                    // Persist the real document witness for mono_faithful proving
                    // (SPEC §3.1.5: raw witness retained for monolithic proving),
                    // SE-wrapped (P1.5) so it can't be lifted off-device.
                    java.util.List<String> docWit = onebit.core.Witness.monoFaithful(wd, 256, 128);
                    Seal.writeFile(
                            new java.io.File(getFilesDir(), "docwit.txt").toPath(),
                            String.join("\n", docWit).getBytes());
                    // Amortized Tier A credential: commit(attributes) once, sealed;
                    // presentations then run present_amortized (~0.8s). See
                    // docs/amortized-enrollment.md.
                    enrollAmortized(dg1, wd, d, t);
                    say("PASSIVE AUTHENTICATION OK — proving CSCA→DSC (enroll, ~10s)…");
                    // Enrollment proof: CSCA(in master list)→DSC, once. ADR-005.
                    proveEnroll(dg1, sod, masterList, d);
                } catch (Throwable ex) {
                    android.util.Log.w("ONEBIT_COVERAGE", "witness: " + ex);
                }
                android.util.Log.i("ONEBIT_COVERAGE", "DSC: " + d.dscInfo
                        + " | docType=" + d.documentCode);
            } catch (Exception e) {
                say("FAIL (closed): " + e);
            }
        }).start();
    }

    private List<X509Certificate> loadMasterList() throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (String name : getAssets().list("masterlist")) {
            if (!name.endsWith(".cer") && !name.endsWith(".pem") && !name.endsWith(".crt")) continue;
            try (InputStream in = getAssets().open("masterlist/" + name)) {
                for (java.security.cert.Certificate c : cf.generateCertificates(in)) {
                    out.add((X509Certificate) c);
                }
            }
        }
        return out;
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }

    private void say(String msg) {
        runOnUiThread(() -> status.setText(msg));
    }
}
