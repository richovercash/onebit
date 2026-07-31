// SPDX-License-Identifier: AGPL-3.0-only
package onebit.wallet;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;

/**
 * The OneBit signature texture as a live Android view: a dot-matrix of small dark
 * cells with orange ones that TWINKLE — each lit cell sparkles on its own Poisson
 * clock (fade-in rise, then fade-out), independently of its neighbours. No global
 * "breathing" swell. Density rises with {@link #setProgress} so the field goes from
 * sparse to filled as a process completes. Canvas-drawn, self-animating.
 *
 * Two tuned looks are used in-app (values dialled in the twinkle lab):
 *  - loader (verify): uniform fill, rate .15, rise .5, fade 1.5, base .11 — the default here
 *  - landing (hero):  rising fill, rate .07, rise .75, fade 1.9, base .17, topClear .21
 *
 * ponytail: one draw loop via postInvalidateOnAnimation; per-cell state reallocated
 * only when the grid dimensions change.
 */
public class DotMatrixView extends View {
    private static final int DARK = 0xFF282828, ORANGE = 0xFFFF5A00, ORANGE_HI = 0xFFFF7A2E;
    private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
    private float stepPx, sizePx;   // grid pitch + cell size (from dp)
    private long t0;
    private boolean running = true;

    // ---- fill ----
    private float topClear = 0f;      // fraction of height kept sparse at the top (hero text)
    private float progress = 1f;      // target fill (1 = full field)
    private float shown = 1f;         // animated fill, eased toward `progress`
    private boolean rising = false;   // false = uniform densify, true = rising waterline
    private float minD = 0f, maxD = 1f;  // density at progress 0 / 1

    // ---- twinkle (defaults = loader look) ----
    private float rate = 0.15f;   // sparkles per lit cell per second
    private float rise = 0.5f;    // fade-in seconds
    private float fade = 1.5f;    // fade-out seconds
    private float base = 0.11f;   // resting glow of a lit cell

    // ---- per-cell twinkle state ----
    private double[] nextSpark, sparkT;
    private int gCols, gRows;

    /** Keep the top `frac` of the field sparse so overlaid text stays readable. */
    public void setTopClear(float frac) { topClear = frac; }

    /** Fill level 0..1: lit density rises with this. Default 1 (full field). */
    public void setProgress(float pr) { progress = pr < 0 ? 0 : pr > 1 ? 1 : pr; }

    /** Advance the fill toward full by one milestone (Zeno step; never quite 1). */
    public void bump() { progress += (1f - progress) * 0.4f; }

    /** true = fill climbs from the bottom (waterline); false = whole field densifies. */
    public void setRising(boolean b) { rising = b; }

    /** density endpoints: sparse (progress 0) .. full (progress 1). */
    public void setDensity(float min, float max) { minD = min; maxD = max; }

    /** twinkle envelope: sparkle rate (/s), fade-in, fade-out (s), resting glow. */
    public void setTwinkle(float rate, float rise, float fade, float base) {
        this.rate = rate; this.rise = rise; this.fade = fade; this.base = base;
    }

    public DotMatrixView(Context c) { this(c, null); }
    public DotMatrixView(Context c, AttributeSet a) {
        super(c, a);
        float d = getResources().getDisplayMetrics().density;
        stepPx = 14 * d;
        sizePx = 10 * d;
        t0 = System.nanoTime();
        setLayerType(LAYER_TYPE_HARDWARE, null);
    }

    /** deterministic per-cell pseudo-random in [0,1) — stable field, so which cells
     *  are lit is steady (only brightness + fill animate). */
    private static float hash(int c, int r) {
        double x = Math.sin(c * 127.1 + r * 311.7) * 43758.5453;
        return (float) (x - Math.floor(x));
    }

    private static float smooth(float t) { return t * t * (3 - 2 * t); }

    /** lit probability for a row-fraction bf (0=top, 1=bottom) at the shown fill. */
    private float dens(float bf) {
        if (bf < topClear) return 0.015f;
        if (rising) {
            float water = 1f - shown;              // below this bf is "filled"
            if (bf >= water) return maxD;
            float edge = Math.max(0f, 1f - (water - bf) / 0.10f);  // soft glowing edge
            return Math.max(minD * 0.4f, maxD * (0.10f + 0.6f * edge * edge));
        }
        return minD + (maxD - minD) * shown;       // uniform densify
    }

    private void ensureGrid(int cols, int rows, double now) {
        if (cols == gCols && rows == gRows && nextSpark != null) return;
        gCols = cols; gRows = rows;
        int n = cols * rows;
        nextSpark = new double[n];
        sparkT = new double[n];
        double mean = 1.0 / Math.max(rate, 0.01);
        for (int i = 0; i < n; i++) {
            nextSpark[i] = now + Math.random() * mean;   // spread first sparkles out
            sparkT[i] = -1e9;
        }
    }

    @Override protected void onDraw(Canvas canvas) {
        int w = getWidth(), h = getHeight();
        if (w == 0 || h == 0) return;
        shown += (progress - shown) * 0.04f;               // ease the fill toward its target
        if (Math.abs(progress - shown) < 0.002f) shown = progress;
        double now = (System.nanoTime() - t0) / 1_000_000_000.0;   // seconds
        int cols = (int) Math.ceil(w / stepPx), rows = (int) Math.ceil(h / stepPx);
        ensureGrid(cols, rows, now);
        double mean = 1.0 / Math.max(rate, 1e-3);
        for (int r = 0; r < rows; r++) {
            float bf = (r + 0.5f) / rows;
            float pr = dens(bf);
            for (int c = 0; c < cols; c++) {
                int i = r * cols + c;
                float x = c * stepPx + 2, y = r * stepPx + 2;
                if (hash(c, r) >= pr) {                    // unlit: dark cell
                    p.setColor(DARK); p.setAlpha(255);
                    canvas.drawRect(x, y, x + sizePx, y + sizePx, p);
                    continue;
                }
                // twinkle: independent Poisson sparkle, rise then fall
                if (rate > 0 && now >= nextSpark[i]) {
                    sparkT[i] = now;
                    nextSpark[i] = now - Math.log(Math.random() + 1e-9) * mean;
                }
                double dt = now - sparkT[i];
                double spark = 0;
                if (dt >= 0) {
                    if (dt < rise) spark = rise > 0 ? smooth((float) (dt / rise)) : 1.0;
                    else spark = Math.exp(-(dt - rise) / fade);
                }
                double b = base + (1 - base) * spark;
                if (b > 1) b = 1;
                p.setColor(b > 0.7 ? ORANGE_HI : ORANGE);
                p.setAlpha((int) (b * 255));
                canvas.drawRect(x, y, x + sizePx, y + sizePx, p);
            }
        }
        if (running) postInvalidateOnAnimation();
    }

    @Override protected void onDetachedFromWindow() { running = false; super.onDetachedFromWindow(); }
    @Override protected void onAttachedToWindow() { super.onAttachedToWindow(); running = true; postInvalidateOnAnimation(); }
}