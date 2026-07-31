// SPDX-License-Identifier: AGPL-3.0-only
package onebit.wallet;

import android.app.Activity;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * On-device UltraHonk proving inside a hidden WebView, fully offline: every
 * request (including the CRS hosts bb.js insists on) is served from bundled
 * assets. The app still has no INTERNET permission — interception happens
 * before any network stack.
 */
final class ZkProver {

    interface Callback {
        void onReady(String backendType);
        void onProof(String resultJson); // {ms, proof: b64, publicInputs: [hex]}
        void onError(String message);
        default void onProgress(String line) {}
    }

    private final WebView web;

    ZkProver(Activity a, Callback cb) {
        this(a, cb, "https://onebit.zk/zk/prove.html");
    }

    ZkProver(Activity a, Callback cb, String pageUrl) {
        web = new WebView(a);
        web.getSettings().setJavaScriptEnabled(true);
        web.addJavascriptInterface(new Object() {
            @JavascriptInterface public void onReady(String t) { a.runOnUiThread(() -> cb.onReady(t)); }
            @JavascriptInterface public void onProof(String r) { a.runOnUiThread(() -> cb.onProof(r)); }
            @JavascriptInterface public void onError(String m) { a.runOnUiThread(() -> cb.onError(m)); }
            @JavascriptInterface public void onProgress(String l) { a.runOnUiThread(() -> cb.onProgress(l)); }
        }, "Android");
        web.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest req) {
                String host = req.getUrl().getHost();
                String path = req.getUrl().getPath();
                try {
                    if (host != null && host.contains("crs.aztec")) {
                        // bb.js CRS download -> bundled points (ranges start at 0)
                        String asset = path.contains("grumpkin") ? "zk/grumpkin_g1.dat"
                                : path.contains("g2") ? "zk/g2.dat" : "zk/g1.dat";
                        return resp(a.getAssets().open(asset), "application/octet-stream");
                    }
                    if ("onebit.zk".equals(host) && path != null && path.startsWith("/zk/")) {
                        return resp(a.getAssets().open(path.substring(1)), mime(path));
                    }
                } catch (Exception e) {
                    return new WebResourceResponse("text/plain", "utf-8", 404, "nf",
                            Map.of(), new ByteArrayInputStream(new byte[0]));
                }
                // default-deny: nothing else resolves (app has no INTERNET anyway)
                return new WebResourceResponse("text/plain", "utf-8", 404, "nf",
                        Map.of(), new ByteArrayInputStream(new byte[0]));
            }
        });
        web.loadUrl(pageUrl);
    }

    /** inputs passed via base64 to avoid JS string-escaping pitfalls */
    void proveB64(String inputsJson) {
        String b64 = android.util.Base64.encodeToString(
                inputsJson.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                android.util.Base64.NO_WRAP);
        web.evaluateJavascript("window.oneBitProve(atob('" + b64 + "'))", null);
    }

    private static WebResourceResponse resp(InputStream in, String mime) {
        Map<String, String> h = new HashMap<>();
        // enable crossOriginIsolated so SharedArrayBuffer/threads can work
        h.put("Cross-Origin-Opener-Policy", "same-origin");
        h.put("Cross-Origin-Embedder-Policy", "require-corp");
        h.put("Cross-Origin-Resource-Policy", "cross-origin");
        h.put("Access-Control-Allow-Origin", "*");
        return new WebResourceResponse(mime, null, 200, "OK", h, in);
    }

    private static String mime(String p) {
        if (p.endsWith(".html")) return "text/html";
        if (p.endsWith(".js") || p.endsWith(".mjs")) return "text/javascript";
        if (p.endsWith(".json")) return "application/json";
        if (p.endsWith(".wasm")) return "application/wasm";
        return "application/octet-stream";
    }
}