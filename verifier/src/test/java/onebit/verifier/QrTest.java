// SPDX-License-Identifier: AGPL-3.0-only
package onebit.verifier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeWriter;

/** P1.5 QR channel: a challenge-sized deep link must survive the QR round trip,
 *  and the gate page must actually carry the SVG. */
public class QrTest {

    // Real challenges (nonce + spki + sig, base64url) run ~1.5-2k chars; use that size.
    private static final String LINK = "onebit://present?c=" + "eyJ2IjoxfQ".repeat(180);

    @Test
    public void deepLinkSurvivesQrRoundTrip() throws Exception {
        BitMatrix m = new QRCodeWriter().encode(LINK, BarcodeFormat.QR_CODE, 1, 1,
                java.util.Map.of(EncodeHintType.MARGIN, 2));
        int w = m.getWidth(), h = m.getHeight();
        int[] px = new int[w * h];
        for (int y = 0; y < h; y++)
            for (int x = 0; x < w; x++)
                px[y * w + x] = m.get(x, y) ? 0x000000 : 0xFFFFFF;
        String decoded = new MultiFormatReader()
                .decode(new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(w, h, px))),
                        java.util.Map.of(com.google.zxing.DecodeHintType.PURE_BARCODE, true))
                .getText();
        assertEquals(LINK, decoded);
    }

    @Test
    public void gatePageCarriesTheQr() {
        String page = DemoServer.gatePage(LINK);
        assertTrue("gate page must embed the QR SVG", page.contains("<svg"));
        assertTrue("deep-link button must remain alongside the QR",
                page.contains("href='" + LINK + "'"));
    }
}
