package onebit.wallet;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Figma "Choose your ID" — two white spec-cards (passport / mobile ID) on the dark
 * ground. Passport -> the reader (MainActivity); mobile ID -> the mDL flow if this
 * build has it (mdl flavor), otherwise a note.
 */
public class ChooseActivity extends Activity {
    static final int BG = 0xFF161616, INK = 0xFF0B0B0B, MUTED = 0xFF7C7C7C,
            WHITE = 0xFFF4F3F1, FAINT = 0xFF6A6A6A, ORANGE = 0xFFFF5A00, ORANGE_DK = 0xFFC64700,
            CARD = 0xFFFBFBFB, LINE = 0xFFD3D3D3;
    float d;
    int dp(float v) { return Math.round(v * d); }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        d = getResources().getDisplayMetrics().density;

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setPadding(dp(24), dp(54), dp(24), dp(24));

        root.addView(kicker("●  ADD A CREDENTIAL"));
        TextView h = new TextView(this);
        h.setText("Where's your ID?");
        h.setTextColor(WHITE);
        h.setTypeface(Typeface.create("sans-serif-black", Typeface.NORMAL));
        h.setTextSize(27);
        h.setLetterSpacing(-0.03f);
        h.setPadding(0, dp(8), 0, dp(22));
        root.addView(h);

        root.addView(card("CHIP · ON-DEVICE", "Tap your passport",
                "Hold it to the back of your phone.",
                v -> startActivity(new Intent(this, MainActivity.class))));
        View gap = new View(this);
        root.addView(gap, new LinearLayout.LayoutParams(-1, dp(12)));
        root.addView(card("MOBILE WALLET", "Add from mobile ID",
                "Share one thing: age over 18.",
                v -> openMdl()));

        View spacer = new View(this);
        root.addView(spacer, new LinearLayout.LayoutParams(-1, 0, 1f));

        TextView foot = new TextView(this);
        foot.setText("Your ID never leaves your phone. Serverless by design — no OneBit server ever sees it.");
        foot.setTextColor(FAINT);
        foot.setTextSize(12);
        foot.setLineSpacing(0, 1.1f);
        root.addView(foot);

        setContentView(root);
    }

    private void openMdl() {
        try {
            Intent i = new Intent();
            i.setClassName(getPackageName(), "onebit.wallet.MdlSchemeActivity");
            startActivity(i);
        } catch (ActivityNotFoundException e) {
            Toast.makeText(this, "Mobile ID needs the OneBit (mDL) build on this device.", Toast.LENGTH_LONG).show();
        }
    }

    private TextView kicker(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextColor(ORANGE);
        t.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        t.setTextSize(11);
        t.setLetterSpacing(0.14f);
        return t;
    }

    /** white spec-card: orange chip + tag/title/desc + chevron. */
    private LinearLayout card(String tag, String title, String desc, View.OnClickListener onClick) {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.HORIZONTAL);
        c.setGravity(Gravity.CENTER_VERTICAL);
        c.setPadding(dp(15), dp(15), dp(15), dp(15));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(CARD);
        bg.setCornerRadius(dp(16));
        bg.setStroke(dp(1), LINE);
        c.setBackground(bg);
        c.setOnClickListener(onClick);
        c.setClickable(true);

        // orange chip with a dark inner "card" glyph
        LinearLayout chip = new LinearLayout(this);
        GradientDrawable cbg = new GradientDrawable();
        cbg.setColor(ORANGE);
        cbg.setCornerRadius(dp(11));
        chip.setBackground(cbg);
        chip.setGravity(Gravity.CENTER);
        View glyph = new View(this);
        GradientDrawable gg = new GradientDrawable();
        gg.setColor(0xFF161616);
        gg.setCornerRadius(dp(3));
        glyph.setBackground(gg);
        chip.addView(glyph, new LinearLayout.LayoutParams(dp(22), dp(15)));
        c.addView(chip, new LinearLayout.LayoutParams(dp(46), dp(46)));

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(14), 0, dp(10), 0);
        TextView tg = new TextView(this);
        tg.setText(tag); tg.setTextColor(ORANGE_DK);
        tg.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        tg.setTextSize(10); tg.setLetterSpacing(0.10f);
        col.addView(tg);
        TextView ti = new TextView(this);
        ti.setText(title); ti.setTextColor(INK);
        ti.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        ti.setTextSize(16.5f); ti.setLetterSpacing(-0.02f);
        ti.setPadding(0, dp(2), 0, dp(2));
        col.addView(ti);
        TextView de = new TextView(this);
        de.setText(desc); de.setTextColor(MUTED); de.setTextSize(13);
        col.addView(de);
        c.addView(col, new LinearLayout.LayoutParams(0, -2, 1f));

        TextView chev = new TextView(this);
        chev.setText("›"); chev.setTextColor(0xFFB4B4B4); chev.setTextSize(22);
        c.addView(chev);
        return c;
    }
}
