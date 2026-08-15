// SPDX-License-Identifier: AGPL-3.0-only
package onebit.wallet;

import android.app.Activity;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.Gravity;
import android.graphics.drawable.GradientDrawable;
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
    private final java.util.List<Runnable> mrzHiders = new java.util.ArrayList<>();   // mask each MRZ field
    private TextView status;
    private NfcAdapter nfc;

    // --- migrated Signal UI: three stages (tap / verify / done) ---
    private android.widget.FrameLayout root;
    private android.view.View tapView, verifyView, doneView;
    private DotMatrixView verifyMatrix;   // the loader's twinkle; fills as steps complete
    private LinearLayout debugBox;
    private float d;
    static final int BG = 0xFF0E0E0E, SCREEN = 0xFF161616, INFO = 0xFFECECEC, INK = 0xFF0B0B0B,
            MUTED = 0xFF8C8C8C, MUTEDL = 0xFF7C7C7C, WHITE = 0xFFF4F3F1, FAINT = 0xFF6A6A6A,
            ORANGE = 0xFFFF5A00, ORANGE_DK = 0xFFC64700, LINE2 = 0xFF3A3A3A;
    static final int STAGE_TAP = 0, STAGE_VERIFY = 1, STAGE_DONE = 2;
    private int dp(float v) { return Math.round(v * d); }
    private TextView tv(String s, int color, float size, String family, float ls) {
        TextView t = new TextView(this);
        t.setText(s); t.setTextColor(color); t.setTextSize(size);
        if (ls != 0) t.setLetterSpacing(ls);
        t.setTypeface(android.graphics.Typeface.create(family, android.graphics.Typeface.BOLD));
        return t;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Android ships a stripped "BC"; replace it with the real one so
        // jmrtd/PA get full algorithm coverage.
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        if (getActionBar() != null) getActionBar().hide();
        d = getResources().getDisplayMetrics().density;
        getWindow().setStatusBarColor(SCREEN);
        getWindow().setNavigationBarColor(SCREEN);

        root = new android.widget.FrameLayout(this);
        root.setBackgroundColor(BG);
        tapView = buildTapView();
        verifyView = buildVerifyView();
        doneView = buildDoneView();
        root.addView(tapView);
        root.addView(verifyView);
        root.addView(doneView);
        setContentView(root);
        showStage(STAGE_TAP);

        // MRZ is session-only PII: never prefilled from disk, never persisted (see enroll path).
        android.text.TextWatcher watcher = new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            public void onTextChanged(CharSequence s, int a, int b, int c) {}
            public void afterTextChanged(android.text.Editable s) { updateReady(); }
        };
        docNo.addTextChangedListener(watcher);
        dob.addTextChangedListener(watcher);
        expiry.addTextChangedListener(watcher);
        updateReady();

        nfc = NfcAdapter.getDefaultAdapter(this);
        handleDeepLink(getIntent());
    }

    private TextView tapNote;

    private void updateReady() { if (tapNote != null) tapNote.setText(readiness()); }

    private void showStage(int stage) {
        runOnUiThread(() -> {
            if (stage == STAGE_VERIFY && verifyMatrix != null) verifyMatrix.setProgress(0.06f); // reset fill
            tapView.setVisibility(stage == STAGE_TAP ? android.view.View.VISIBLE : android.view.View.GONE);
            verifyView.setVisibility(stage == STAGE_VERIFY ? android.view.View.VISIBLE : android.view.View.GONE);
            doneView.setVisibility(stage == STAGE_DONE ? android.view.View.VISIBLE : android.view.View.GONE);
        });
    }

    // ---- STAGE: passport tap ----
    private android.view.View buildTapView() {
        ScrollView sv = new ScrollView(this);
        sv.setFillViewport(true);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(24), dp(50), dp(24), dp(24));
        sv.addView(col);

        TextView kick = tv("●  PASSPORT", ORANGE, 11, "sans-serif-medium", 0.14f);
        kick.setOnLongClickListener(v -> {  // long-press reveals dev tools
            debugBox.setVisibility(debugBox.getVisibility() == android.view.View.GONE
                    ? android.view.View.VISIBLE : android.view.View.GONE);
            return true;
        });
        col.addView(kick);
        TextView h = tv("Enter Passport Details", WHITE, 25, "sans-serif-black", -0.03f);
        h.setPadding(0, dp(8), 0, dp(18));
        h.setLineSpacing(0, 1.04f);
        col.addView(h);

        mrzHiders.clear();
        docNo = darkField("Document number");
        // passport numbers are ICAO-9303 alphanumeric (letters allowed) -> text keyboard,
        // but CAPS + visible-password so the keyboard never suggests or stores it.
        docNo.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
                | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        col.addView(revealRow(docNo));

        LinearLayout dates = new LinearLayout(this);
        dates.setOrientation(LinearLayout.HORIZONTAL);
        dob = darkField("DOB YYMMDD");
        expiry = darkField("Exp YYMMDD");
        dob.setInputType(InputType.TYPE_CLASS_NUMBER);
        expiry.setInputType(InputType.TYPE_CLASS_NUMBER);
        dob.setTextSize(13.5f); expiry.setTextSize(13.5f);   // fit "Expiry YYMMDD" beside the eye
        expiry.setImeOptions(android.view.inputmethod.EditorInfo.IME_ACTION_DONE);
        dates.addView(revealRow(dob), new LinearLayout.LayoutParams(0, -2, 1f));
        dates.addView(new android.view.View(this), new LinearLayout.LayoutParams(dp(10), 1));
        dates.addView(revealRow(expiry), new LinearLayout.LayoutParams(0, -2, 1f));
        LinearLayout.LayoutParams datesLp = new LinearLayout.LayoutParams(-1, -2);
        datesLp.topMargin = dp(20);   // 20dp between the passport number and the date row
        col.addView(dates, datesLp);

        // primary action: hide the details, then cue the NFC tap
        TextView scan = tv("Scan Passport", 0xFF111111, 15, "sans-serif-medium", 0f);
        scan.setTypeface(android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.BOLD));
        scan.setGravity(Gravity.CENTER);
        scan.setPadding(0, dp(15), 0, dp(15));
        GradientDrawable sb = new GradientDrawable();
        sb.setColor(ORANGE); sb.setCornerRadius(dp(13));
        scan.setBackground(sb);
        scan.setOnClickListener(v -> onScanClicked());
        LinearLayout.LayoutParams scanLp = new LinearLayout.LayoutParams(-1, -2);
        scanLp.topMargin = dp(28);
        col.addView(scan, scanLp);

        TextView cap = tv("Hold it to the back of your phone", MUTED, 12.5f, "sans-serif", 0f);
        cap.setGravity(Gravity.CENTER);
        cap.setPadding(0, dp(12), 0, 0);
        col.addView(cap);

        tapNote = new TextView(this);
        tapNote.setTextColor(FAINT); tapNote.setTextSize(12.5f);
        tapNote.setGravity(Gravity.CENTER);
        tapNote.setPadding(0, dp(10), 0, dp(8));
        col.addView(tapNote);

        debugBox = new LinearLayout(this);
        debugBox.setOrientation(LinearLayout.VERTICAL);
        debugBox.setVisibility(android.view.View.GONE);
        addDbg(debugBox, "Attest device key (T3 demo)", v -> Attest.run(this, "demo-verifier-01", this::say));
        addDbg(debugBox, "Native prove (slim, JNI)", v -> nativeProveTest("zk/mono_slim.json", "zk/wit_slim.txt", "slim"));
        addDbg(debugBox, "Native prove (recursion 775k)", v -> nativeProveTest("zk/circuit_p.json", "zk/wit_p.txt", "recursion-775k"));
        addBench(debugBox, "Bench: recursion", "c=circuit_p_v1.json&i=bench_p_inputs.json&l=recursion-775k");
        addBench(debugBox, "Bench: monolithic", "c=circuit_mono.json&i=mono_inputs.json&l=monolithic-177k");
        col.addView(debugBox);
        return sv;
    }

    private EditText darkField(String hint) {
        EditText e = new EditText(this);
        e.setHint(hint); e.setHintTextColor(FAINT); e.setTextColor(WHITE); e.setTextSize(15);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xFF1B1B1B); bg.setCornerRadius(dp(11)); bg.setStroke(dp(1), LINE2);
        e.setBackground(bg);
        e.setPadding(dp(14), dp(12), dp(14), dp(12));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(8);
        e.setLayoutParams(lp);
        return e;
    }

    /** Wrap a sensitive field with an inline lucide eye/eye-off toggle. Defaults to
     *  REVEAL; each field also registers a hider so "Scan Passport" can mask them all. */
    private android.view.View revealRow(EditText e) {
        e.setPadding(dp(14), dp(12), dp(40), dp(12));                    // room for the eye icon
        android.widget.FrameLayout f = new android.widget.FrameLayout(this);
        f.addView(e, new android.widget.FrameLayout.LayoutParams(-1, -2));

        EyeIcon eye = new EyeIcon(this);
        // bounded height (not MATCH_PARENT — that stretches the wrap-content row)
        android.widget.FrameLayout.LayoutParams elp = new android.widget.FrameLayout.LayoutParams(
                dp(40), dp(44), Gravity.END | Gravity.CENTER_VERTICAL);
        f.addView(eye, elp);

        Runnable hide = () -> { e.setTransformationMethod(new PasswordTransformationMethod()); eye.setOff(true); };
        Runnable reveal = () -> { e.setTransformationMethod(null); eye.setOff(false); };
        reveal.run();                    // default: reveal mode
        mrzHiders.add(hide);
        eye.setOnClickListener(v -> {
            if (eye.isOff()) reveal.run(); else hide.run();
            e.setSelection(e.getText().length());   // keep the caret at the end after toggling
        });

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(12);
        f.setLayoutParams(lp);
        return f;
    }

    /** "Scan Passport": hide the entered details, drop the keyboard, and cue the tap.
     *  The actual read is NFC-triggered (onTag); this arms the privacy state. */
    private void onScanClicked() {
        for (Runnable hide : mrzHiders) hide.run();     // fields -> hidden
        android.view.inputmethod.InputMethodManager imm =
                getSystemService(android.view.inputmethod.InputMethodManager.class);
        if (imm != null && getCurrentFocus() != null)
            imm.hideSoftInputFromWindow(getCurrentFocus().getWindowToken(), 0);
        String ready = readiness();
        tapNote.setText(ready.startsWith("Ready") ? "Hold it to the back of your phone." : ready);
    }

    private void addDbg(LinearLayout box, String label, android.view.View.OnClickListener onClick) {
        TextView b = new TextView(this);
        b.setText(label); b.setTextColor(MUTED); b.setTextSize(12);
        b.setTypeface(android.graphics.Typeface.MONOSPACE);
        b.setPadding(dp(12), dp(10), dp(12), dp(10));
        GradientDrawable bg = new GradientDrawable(); bg.setStroke(dp(1), LINE2); bg.setCornerRadius(dp(8));
        b.setBackground(bg);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2); lp.topMargin = dp(8);
        b.setLayoutParams(lp);
        b.setOnClickListener(v -> { showStage(STAGE_VERIFY); onClick.onClick(v); });
        box.addView(b);
    }

    /** Which rail the enrolled credential came from, for the header label. mDL enrolment
     *  writes credtype="bool" (it commits over/threshold, not a dob — see Present.java);
     *  no file yet means nothing is enrolled, and passport is this build's default read. */
    private String sourceLabel() {
        try {
            if (new String(java.nio.file.Files.readAllBytes(
                    new java.io.File(getFilesDir(), "credtype.txt").toPath()),
                    java.nio.charset.StandardCharsets.UTF_8).trim().equals("bool"))
                return "READING MOBILE ID";
        } catch (Exception e) { /* not enrolled yet */ }
        return "READING PASSPORT";
    }
    // ponytail: read once, at view-build time in onCreate — so enrolling mid-session
    // leaves a stale header until restart. Move the call into the stage transition if
    // that ever shows up in a demo.

    // ---- STAGE: verify & seal (twinkle loader + live status) ----
    private android.view.View buildVerifyView() {
        android.widget.FrameLayout f = new android.widget.FrameLayout(this);
        f.setBackgroundColor(SCREEN);
        verifyMatrix = new DotMatrixView(this);   // uniform loader twinkle, fills with progress
        verifyMatrix.setRising(false);
        verifyMatrix.setDensity(0.0f, 1.0f);
        verifyMatrix.setTwinkle(0.15f, 0.5f, 1.5f, 0.11f);   // loader look (twinkle lab)
        verifyMatrix.setProgress(0.06f);          // starts nearly empty; bump() fills it in
        f.addView(verifyMatrix, new android.widget.FrameLayout.LayoutParams(-1, -1));

        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.VERTICAL);
        top.setPadding(dp(24), dp(50), dp(24), dp(24));
        top.addView(tv("●  " + sourceLabel(), ORANGE, 11, "sans-serif-medium", 0.14f));
        TextView vh = tv("Verifying & sealing", WHITE, 26, "sans-serif-black", -0.03f);
        vh.setPadding(0, dp(8), 0, 0);
        top.addView(vh);
        f.addView(top);

        status = new TextView(this);
        status.setTextColor(WHITE); status.setTextSize(13.5f);
        status.setLineSpacing(0, 1.25f);
        LinearLayout bottom = new LinearLayout(this);
        bottom.setBackgroundColor(0xE60E0E0E);
        bottom.setPadding(dp(24), dp(18), dp(24), dp(30));
        bottom.addView(status);
        android.widget.FrameLayout.LayoutParams blp =
                new android.widget.FrameLayout.LayoutParams(-1, -2, Gravity.BOTTOM);
        f.addView(bottom, blp);
        return f;
    }

    // ---- STAGE: done (dot-matrix "18+" payoff) ----
    private android.view.View buildDoneView() {
        LinearLayout rootv = new LinearLayout(this);
        rootv.setOrientation(LinearLayout.VERTICAL);
        rootv.setBackgroundColor(BG);

        android.widget.FrameLayout disp = new android.widget.FrameLayout(this);
        disp.setBackgroundColor(SCREEN);
        DotMatrixView mx = new DotMatrixView(this);
        mx.setTopClear(0.42f);
        mx.setRising(true);                       // sealed payoff: rich rising field under "18+"
        mx.setDensity(0.27f, 1.0f);
        mx.setTwinkle(0.07f, 0.75f, 1.9f, 0.17f);
        disp.addView(mx, new android.widget.FrameLayout.LayoutParams(-1, -1));
        LinearLayout hero = new LinearLayout(this);
        hero.setOrientation(LinearLayout.VERTICAL);
        hero.setPadding(dp(24), dp(50), dp(24), dp(24));
        hero.addView(tv("●  SEALED ON THIS DEVICE", ORANGE, 11, "sans-serif-medium", 0.14f));
        TextView giant = new TextView(this);
        giant.setText("18+");
        giant.setTextColor(WHITE);
        giant.setTypeface(android.graphics.Typeface.create("sans-serif-black", android.graphics.Typeface.NORMAL));
        giant.setTextSize(84);
        giant.setLetterSpacing(-0.04f);
        giant.setPadding(0, dp(8), 0, 0);
        android.text.SpannableString ss = new android.text.SpannableString("18+");
        ss.setSpan(new android.text.style.ForegroundColorSpan(ORANGE), 2, 3, 0);
        giant.setText(ss);
        hero.addView(giant);
        disp.addView(hero, new android.widget.FrameLayout.LayoutParams(-1, -2, Gravity.TOP));
        rootv.addView(disp, new LinearLayout.LayoutParams(-1, 0, 1f));

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.VERTICAL);
        bar.setBackgroundColor(INFO);
        bar.setPadding(dp(22), dp(18), dp(22), dp(24));
        bar.addView(tv("●  AGE CREDENTIAL", MUTEDL, 10.5f, "sans-serif-medium", 0.10f));
        TextView v = tv("Over 18 — verified", INK, 18, "sans-serif-medium", -0.02f);
        v.setPadding(0, dp(3), 0, dp(3));
        bar.addView(v);
        bar.addView(tv("SEALED · SECURE HARDWARE", MUTEDL, 10.5f, "sans-serif-medium", 0.06f));
        TextView done = tv("Done", WHITE, 15, "sans-serif-medium", 0);
        done.setGravity(Gravity.CENTER); done.setPadding(0, dp(15), 0, dp(15));
        GradientDrawable db = new GradientDrawable(); db.setColor(0xFF111111); db.setCornerRadius(dp(13));
        done.setBackground(db);
        LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(-1, -2); dlp.topMargin = dp(16);
        done.setLayoutParams(dlp);
        done.setOnClickListener(x -> { startActivity(new android.content.Intent(this, WelcomeActivity.class)); finish(); });
        bar.addView(done);
        rootv.addView(bar, new LinearLayout.LayoutParams(-1, -2));
        return rootv;
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

    /** Amortized Tier A enrollment — BOOLEAN commit (no birthdate retained). We
     *  resolve the birthdate only to compute the age bit, then commit
     *  C = Poseidon2([over, threshold, doc_hash, k, salt]) via commit_fields and
     *  seal it (over, threshold, doc_hash, k, salt, C) + credtype="bool". The dob is
     *  never stored — presentations use present_bool, identical to the mDL path.
     *  Provenance is carried by passive auth (already verified) + attestation. */
    private void enrollAmortized(byte[] dg1, onebit.core.Witness.Doc wd,
                                 PassiveAuth.MrzData d, java.time.LocalDate t) {
        try {
            java.io.File g1 = new java.io.File(getExternalFilesDir(null), "g1_big.dat");
            if (!g1.exists()) { say("Amortized enroll skipped (SRS missing)."); return; }
            java.time.LocalDate dob = Mrz.resolve(d.dateOfBirth, t);
            int dobI = dob.getYear() * 10000 + dob.getMonthValue() * 100 + dob.getDayOfMonth();
            int enrollDate = t.getYear() * 10000 + t.getMonthValue() * 100 + t.getDayOfMonth();
            int threshold = 18;
            int over = (dobI + threshold * 10000 <= enrollDate) ? 1 : 0;   // dob discarded after this

            java.math.BigInteger P = new java.math.BigInteger(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617");
            java.math.BigInteger docHash = new java.math.BigInteger(1,
                    java.security.MessageDigest.getInstance("SHA-256").digest(wd.eContent)).mod(P);
            java.math.BigInteger k = new java.math.BigInteger(250, new java.security.SecureRandom());
            java.math.BigInteger salt = new java.math.BigInteger(250, new java.security.SecureRandom());

            String w = over + "\n" + threshold + "\n" + docHash + "\n" + k + "\n" + salt;
            byte[] proof = NativeProver.prove(readAsset("zk/commit_fields.json"), w, g1.getAbsolutePath(), false);
            String cField = pubField(proof, 0);   // C
            String blob = over + "\n" + threshold + "\n" + docHash + "\n" + k + "\n" + salt + "\n" + cField;
            Seal.writeFile(new java.io.File(getFilesDir(), "acred.bin").toPath(), blob.getBytes());
            java.nio.file.Files.write(new java.io.File(getFilesDir(), "credtype.txt").toPath(), "bool".getBytes());
            say("Amortized credential enrolled (age " + threshold + "+ = " + (over == 1)
                    + ") — ~0.8s presentations, no birthdate retained.");
        } catch (Throwable ex) {
            android.util.Log.w("ONEBIT_ACRED", "amortized enroll: " + ex);
            say("Amortized enroll skipped: " + ex);
        }
    }

    /** Amortized Tier A enrollment from an ISO 18013-5 mDL (mobile driver's
     *  license): verify the mdoc (Mdl passive auth), derive (dob, expiry,
     *  doc_hash), compute C via commit_fields, seal acred.bin. Presentations then
     *  use present_amortized unchanged — an mDL credential is indistinguishable
     *  from a passport one on the wire. */
    private void enrollMdl() {
        try {
            byte[] mdoc = readAssetBytes("mdl/test_mdl.cbor");
            byte[] iacaDer = readAssetBytes("mdl/test_iaca.der");
            java.security.cert.X509Certificate iaca = (java.security.cert.X509Certificate)
                    java.security.cert.CertificateFactory.getInstance("X.509")
                            .generateCertificate(new java.io.ByteArrayInputStream(iacaDer));
            onebit.core.Mdl.MdlData d = onebit.core.Mdl.verify(mdoc, java.util.List.of(iaca));
            java.io.File g1 = new java.io.File(getExternalFilesDir(null), "g1_big.dat");
            if (!g1.exists()) { say("mDL enroll skipped (SRS missing)."); return; }
            java.math.BigInteger P = new java.math.BigInteger(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617");
            java.math.BigInteger docHash = new java.math.BigInteger(1,
                    java.security.MessageDigest.getInstance("SHA-256").digest(d.msoBytes)).mod(P);
            java.math.BigInteger k = new java.math.BigInteger(250, new java.security.SecureRandom());
            java.math.BigInteger salt = new java.math.BigInteger(250, new java.security.SecureRandom());
            String w = d.dob + "\n" + d.expiry + "\n" + docHash + "\n" + k + "\n" + salt;
            byte[] proof = NativeProver.prove(readAsset("zk/commit_fields.json"), w, g1.getAbsolutePath(), false);
            String c = pubField(proof, 0);
            String blob = d.dob + "\n" + d.expiry + "\n" + docHash + "\n" + k + "\n" + salt + "\n" + c;
            Seal.writeFile(new java.io.File(getFilesDir(), "acred.bin").toPath(), blob.getBytes());
            say("mDL ENROLLED (ISO 18013-5) — dob " + d.dob + ", expiry " + d.expiry
                    + ". Presentations now ~0.8s (Tier A), unchanged circuit.");
        } catch (Throwable ex) {
            android.util.Log.w("ONEBIT_MDL", "mdl enroll: " + ex);
            say("mDL enroll failed: " + ex);
        }
    }

    private byte[] readAssetBytes(String path) throws Exception {
        try (java.io.InputStream in = getAssets().open(path)) { return in.readAllBytes(); }
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
        String kSealed = android.util.Base64.encodeToString(
                Seal.wrap(k.toString().getBytes()), android.util.Base64.NO_WRAP);
        // Only the SE-wrapped nullifier key is persisted. Birth/expiry dates are NOT
        // retained — they were dead PII (never read back); the age bit is committed in
        // acred.bin (boolean) and the dob is discarded right after.
        getSharedPreferences("cred", MODE_PRIVATE).edit()
                .putString("k", kSealed)
                .apply();
    }

    private void handleDeepLink(android.content.Intent intent) {
        android.net.Uri u = intent == null ? null : intent.getData();
        if (u == null || !"onebit".equals(u.getScheme())) return;
        // Dev/demo entry points (benchp: heavy native proving; enrollmdl: inject the
        // bundled test credential, overwriting acred.bin) must never be web-triggerable.
        // A browser navigating to onebit:// adds CATEGORY_BROWSABLE; adb `am start` does
        // not — so gate these on the absence of that category. Keeps the demo path
        // working while blocking a malicious page from firing them silently.
        boolean fromWeb = intent.hasCategory(android.content.Intent.CATEGORY_BROWSABLE);
        // P1.0 spike: adb-triggerable native recursion bench (no UI tap needed).
        //   adb shell am start -a android.intent.action.VIEW -d onebit://benchp
        // Read the result: adb logcat -s ONEBIT_NATIVE  ->  PROVE OK [recursion-775k]
        if ("benchp".equals(u.getHost())) {
            if (fromWeb) { say("Dev deep link refused (browser)."); return; }
            nativeProveTest("zk/circuit_p.json", "zk/wit_p.txt", "recursion-775k");
            return;
        }
        // Demo: enroll the bundled test mDL (Tier A). adb shell am start -d onebit://enrollmdl
        if ("enrollmdl".equals(u.getHost())) {
            if (fromWeb) { say("Demo deep link refused (browser)."); return; }
            new Thread(this::enrollMdl).start();
            return;
        }
        String c = u.getQueryParameter("c");
        if (c == null) { say("Deep link missing challenge."); return; }
        String json = new String(android.util.Base64.decode(c,
                android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING),
                java.nio.charset.StandardCharsets.UTF_8);
        // Don't jump to the "sealing" screen yet — Present may refuse upfront (e.g. a
        // person-bound policy). It calls back once all checks pass and proving begins.
        new Present(this, this::say, () -> showStage(STAGE_VERIFY)).start(json);
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
            android.os.Bundle opts = new android.os.Bundle();
            // Wait longer before deciding the tag left — old/slow chips drop briefly mid-read.
            opts.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 5000);
            nfc.enableReaderMode(this, this::onTag,
                    NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B
                            | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, opts);
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
        // used only in-memory for the BAC key below — never written to disk.
        showStage(STAGE_VERIFY);
        say("Tag detected, reading chip…");
        new Thread(() -> {
            IsoDep isoDep = IsoDep.get(tag);
            if (isoDep == null) { say("FAIL (closed): not an ISO-DEP e-passport chip."); return; }
            isoDep.setTimeout(20000);       // older/slow chips need a longer transceive window
            boolean pacePossible = true;    // probe PACE once; old BAC-only docs skip it on retries
            Exception last = null;
            for (int attempt = 1; attempt <= 3; attempt++) {
                try {
                    if (!isoDep.isConnected()) isoDep.connect();
                    CardService cs = new IsoDepCardService(isoDep);
                    PassportService ps = new PassportService(cs,
                            PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                            PassportService.DEFAULT_MAX_BLOCKSIZE, false, false);
                    ps.open();
                    BACKey bacKey = new BACKey(doc, birth, exp);
                    boolean paceOk = false;
                    if (pacePossible) {         // modern docs may be PACE-only; older ones are BAC-only
                        try {
                            org.jmrtd.lds.CardAccessFile caf = new org.jmrtd.lds.CardAccessFile(
                                    ps.getInputStream(PassportService.EF_CARD_ACCESS));
                            for (org.jmrtd.lds.SecurityInfo si : caf.getSecurityInfos()) {
                                if (si instanceof org.jmrtd.lds.PACEInfo) {
                                    org.jmrtd.lds.PACEInfo pi = (org.jmrtd.lds.PACEInfo) si;
                                    say("PACE…");
                                    ps.doPACE(org.jmrtd.PACEKeySpec.createMRZKey(bacKey),
                                            pi.getObjectIdentifier(),
                                            org.jmrtd.lds.PACEInfo.toParameterSpec(pi.getParameterId()),
                                            pi.getParameterId());
                                    paceOk = true;
                                    break;
                                }
                            }
                        } catch (Exception pe) {
                            pacePossible = false;   // no CardAccess -> older BAC-only doc; don't re-probe on retries
                            say("No PACE (older document) — using BAC…");
                        }
                    }
                    ps.sendSelectApplet(paceOk);
                    if (!paceOk) ps.doBAC(bacKey);
                    say("Access established (try " + attempt + ") — reading DG1 + SOD…");
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
                        // Persist the real document witness for faithful proving, SE-wrapped.
                        java.util.List<String> docWit = onebit.core.Witness.presentationWitness(wd, 256, 128);
                        Seal.writeFile(
                                new java.io.File(getFilesDir(), "docwit.txt").toPath(),
                                String.join("\n", docWit).getBytes());
                        java.nio.file.Files.write(
                                new java.io.File(getFilesDir(), "presalg.txt").toPath(), wd.presCircuit.getBytes());
                        // Amortized Tier A credential: commit(bool) once, sealed; presentations
                        // then run present_bool (~0.8s).
                        enrollAmortized(dg1, wd, d, t);
                        // Faithful CSCA→DSC enroll proof (Tier B, ADR-005) is OPTIONAL and needs a
                        // large SRS; gate it so a small present-sized SRS can't make the native
                        // prover abort (SIGABRT). Off by default.
                        if (new java.io.File(getFilesDir(), "faithful").exists()) {
                            say("Proving CSCA→DSC (enroll, ~10s)…");
                            proveEnroll(dg1, sod, masterList, d);
                        }
                    } catch (Throwable ex) {
                        android.util.Log.w("ONEBIT_COVERAGE", "witness: " + ex);
                    }
                    android.util.Log.i("ONEBIT_COVERAGE", "DSC: " + d.dscInfo
                            + " | docType=" + d.documentCode);
                    runOnUiThread(() -> {   // wipe the MRZ from the inputs once the bit is sealed
                        docNo.setText(""); dob.setText(""); expiry.setText("");
                    });
                    showStage(STAGE_DONE);
                    return;   // SUCCESS — done
                } catch (Exception e) {
                    last = e;
                    android.util.Log.w("ONEBIT_READ", "read attempt " + attempt + " failed: " + e);
                    if (attempt < 3) {
                        say("Read hiccup (try " + attempt + "/3) — keep the passport still…");
                        try { isoDep.close(); } catch (Exception ignore) {}
                        try { Thread.sleep(400); isoDep.connect(); } catch (Exception ce) { last = ce; }
                    }
                }
            }
            String m = String.valueOf(last).toLowerCase();
            String hint = (m.contains("bac") || m.contains("6300") || m.contains("6982") || m.contains("access denied"))
                    ? "double-check the document number, date of birth and expiry — they must match the passport exactly"
                    : "keep the passport flat and still on the upper-center back of the phone";
            say("FAIL (closed) after 3 tries — " + hint + ".  [" + last + "]");
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
        android.util.Log.i("ONEBIT_READ", msg);   // durable trace (status flashes by on the UI)
        runOnUiThread(() -> {
            if (verifyView.getVisibility() == android.view.View.VISIBLE) {
                status.setText(msg);
                if (verifyMatrix != null) verifyMatrix.bump();   // each milestone rises the fill
            } else {
                // no progress screen up (e.g. an upfront refusal, before proving) — surface it
                android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_LONG).show();
            }
        });
    }
}