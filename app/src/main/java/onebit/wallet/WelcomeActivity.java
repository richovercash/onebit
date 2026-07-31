package onebit.wallet;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Product entry screen — the Figma "Welcome" frame in the Signal look: a dark
 * dot-matrix hero ("1 bit.") over a light info bar with the pitch + a single CTA.
 * "Get started" opens the reader (MainActivity). First migrated screen; the rest
 * of the enroll flow follows the same spec-card grammar.
 */
public class WelcomeActivity extends Activity {
    // design tokens (Figma "Signal")
    static final int BG = 0xFF0E0E0E, SCREEN = 0xFF161616, INFO = 0xFFECECEC,
            INK = 0xFF0B0B0B, MUTED = 0xFF7C7C7C, WHITE = 0xFFF4F3F1, ORANGE = 0xFFFF5A00;
    float d;
    int dp(float v) { return Math.round(v * d); }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        d = getResources().getDisplayMetrics().density;

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);

        // --- dark display zone with the twinkle matrix + top-aligned hero text ---
        FrameLayout display = new FrameLayout(this);
        display.setBackgroundColor(SCREEN);
        DotMatrixView matrix = new DotMatrixView(this);
        // landing look (twinkle lab): slow twinkle filling the whole display down to the info bar
        matrix.setTopClear(0f);          // fill the screen (hero text overlays the dim field)
        matrix.setRising(true);
        matrix.setDensity(0.27f, 1.0f);
        matrix.setTwinkle(0.07f, 0.75f, 1.9f, 0.17f);
        // progress stays 1 (static hero — full field, no fill motion)
        display.addView(matrix, new FrameLayout.LayoutParams(-1, -1));

        LinearLayout hero = new LinearLayout(this);
        hero.setOrientation(LinearLayout.VERTICAL);
        hero.setPadding(dp(24), dp(52), dp(24), dp(24));
        hero.addView(label("●  PRIVATE AGE CHECK", ORANGE));
        TextView giant = new TextView(this);
        giant.setText("OneBit.");
        giant.setTextColor(WHITE);
        giant.setTypeface(Typeface.create("sans-serif-black", Typeface.NORMAL));
        giant.setTextSize(64);
        giant.setLetterSpacing(-0.03f);
        giant.setPadding(0, dp(10), 0, 0);
        hero.addView(giant);
        display.addView(hero, new FrameLayout.LayoutParams(-1, -2, Gravity.TOP));
        root.addView(display, new LinearLayout.LayoutParams(-1, 0, 1f));

        // --- light info bar ---
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.VERTICAL);
        bar.setBackgroundColor(INFO);
        bar.setPadding(dp(22), dp(20), dp(22), dp(24));

        TextView head = new TextView(this);
        head.setText("Prove you're old enough.\nReveal nothing else.");
        head.setTextColor(INK);
        head.setTypeface(Typeface.create("sans-serif-black", Typeface.NORMAL));
        head.setTextSize(20);
        head.setLetterSpacing(-0.02f);
        head.setLineSpacing(0, 1.05f);
        bar.addView(head);

        TextView sub = new TextView(this);
        sub.setText("One sealed fact — are you over 18? No name, no account, no uploads.");
        sub.setTextColor(MUTED);
        sub.setTextSize(13);
        sub.setPadding(0, dp(8), 0, dp(16));
        bar.addView(sub);

        TextView cta = new TextView(this);
        cta.setText("Get started");
        cta.setTextColor(0xFF111111);
        cta.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        cta.setTextSize(15);
        cta.setGravity(Gravity.CENTER);
        cta.setPadding(0, dp(15), 0, dp(15));
        GradientDrawable btnBg = new GradientDrawable();
        btnBg.setColor(ORANGE);
        btnBg.setCornerRadius(dp(13));
        cta.setBackground(btnBg);
        cta.setOnClickListener(v -> startActivity(new Intent(this, ChooseActivity.class)));
        bar.addView(cta);

        root.addView(bar, new LinearLayout.LayoutParams(-1, -2));
        setContentView(root);
    }

    private TextView label(String text, int color) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextColor(color);
        t.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        t.setTextSize(11);
        t.setLetterSpacing(0.14f);
        return t;
    }
}
