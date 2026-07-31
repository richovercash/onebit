package onebit.wallet;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.view.View;

/**
 * Minimal lucide-style eye / eye-off icon (stroke only) for the MRZ show/hide toggle.
 * Compact so it frees width for the field hint. off=true draws eye-off (field hidden).
 * ponytail: hand-drawn on Canvas (approximates lucide's 24×24 paths) — no vector asset,
 * no res/ dir; this app is 100% programmatic.
 */
public class EyeIcon extends View {
    private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final float density;
    private boolean off = false;   // true = eye-off => the field is masked

    public EyeIcon(Context c) {
        super(c);
        density = getResources().getDisplayMetrics().density;
        p.setStyle(Paint.Style.STROKE);
        p.setStrokeCap(Paint.Cap.ROUND);
        p.setStrokeJoin(Paint.Join.ROUND);
        p.setColor(0xFFFF5A00);   // ORANGE
    }

    public void setOff(boolean o) { off = o; invalidate(); }
    public boolean isOff() { return off; }

    @Override protected void onDraw(Canvas cv) {
        float target = 18 * density;                 // draw an 18dp glyph, centred in the touch area
        float s = target / 24f;                      // lucide viewBox is 24×24
        float ox = (getWidth() - target) / 2f, oy = (getHeight() - target) / 2f;
        p.setStrokeWidth(1.4f * s);   // thin lucide-weight stroke
        cv.save();
        cv.translate(ox, oy);
        cv.scale(s, s);
        // almond eye outline
        Path eye = new Path();
        eye.moveTo(2, 12);
        eye.quadTo(12, 4, 22, 12);
        eye.quadTo(12, 20, 2, 12);
        eye.close();
        cv.drawPath(eye, p);
        cv.drawCircle(12, 12, 3.2f, p);              // pupil
        if (off) cv.drawLine(3.2f, 3.2f, 20.8f, 20.8f, p);   // slash => hidden
        cv.restore();
    }
}
