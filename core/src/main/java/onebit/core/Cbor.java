// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal CBOR (RFC 8949) for the ISO 18013-5 mdoc subset: unsigned ints, byte
 * strings, text strings, arrays, maps, tags, booleans. Enough to build and parse
 * an mDL's COSE_Sign1 / MobileSecurityObject / IssuerSignedItem — no float, no
 * indefinite-length, no negative-int maps needed here. Hand-rolled to keep the
 * wallet dependency-free (mirrors the hand-rolled ASN.1 offset handling for
 * passports).
 *
 * Decoding preserves the raw bytes of byte strings, and `readSpan` returns the
 * exact encoded span of the next item — needed because mdoc digests are taken
 * over precise byte sequences (IssuerSignedItemBytes), not re-encodings.
 */
public final class Cbor {

    /** A CBOR tag (major type 6): tag number + already-encoded/parsed content. */
    public static final class Tag {
        public final long n;
        public final Object v;
        public Tag(long n, Object v) { this.n = n; this.v = v; }
    }

    // ---- encoding ----
    static byte[] head(int major, long v) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        int m = major << 5;
        if (v < 24) o.write(m | (int) v);
        else if (v < (1L << 8)) { o.write(m | 24); o.write((int) v); }
        else if (v < (1L << 16)) { o.write(m | 25); w(o, v, 2); }
        else if (v < (1L << 32)) { o.write(m | 26); w(o, v, 4); }
        else { o.write(m | 27); w(o, v, 8); }
        return o.toByteArray();
    }
    static void w(ByteArrayOutputStream o, long v, int n) { for (int i = n - 1; i >= 0; i--) o.write((int) (v >> (8 * i)) & 0xff); }
    static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.writeBytes(p);
        return o.toByteArray();
    }

    public static byte[] uint(long v) { return head(0, v); }
    public static byte[] nint(long v) { return head(1, -1 - v); }    // negative int (v < 0)
    public static byte[] nul() { return new byte[]{(byte) 0xf6}; }   // simple value 22 = null
    public static byte[] bstr(byte[] b) { return cat(head(2, b.length), b); }
    public static byte[] tstr(String s) { byte[] b = s.getBytes(StandardCharsets.UTF_8); return cat(head(3, b.length), b); }
    public static byte[] bool(boolean x) { return new byte[]{(byte) (x ? 0xf5 : 0xf4)}; }
    public static byte[] tag(long t, byte[] content) { return cat(head(6, t), content); }
    public static byte[] array(byte[]... items) { return cat(head(4, items.length), cat(items)); }
    /** map from k/v pairs already encoded, in the given (insertion) order. */
    public static byte[] map(byte[]... kv) {
        if (kv.length % 2 != 0) throw new IllegalArgumentException("odd kv");
        return cat(head(5, kv.length / 2), cat(kv));
    }

    // ---- decoding ----
    public static final class Cur { public final byte[] b; public int p; Cur(byte[] b, int p) { this.b = b; this.p = p; } }

    public static Object decode(byte[] b) { return read(new Cur(b, 0)); }

    /** Raw encoded byte span of the next item (advances the cursor past it). */
    public static byte[] readSpan(Cur c) {
        int start = c.p;
        skip(c);
        return java.util.Arrays.copyOfRange(c.b, start, c.p);
    }

    static long len(Cur c, int ai) {
        if (ai < 24) return ai;
        long v = 0; int n = ai == 24 ? 1 : ai == 25 ? 2 : ai == 26 ? 4 : 8;
        for (int i = 0; i < n; i++) v = (v << 8) | (c.b[c.p++] & 0xff);
        return v;
    }

    public static Object read(Cur c) {
        int ib = c.b[c.p++] & 0xff, major = ib >> 5, ai = ib & 0x1f;
        switch (major) {
            case 0: return len(c, ai);                                  // Long
            case 1: return -1 - len(c, ai);
            case 2: { int n = (int) len(c, ai); byte[] o = java.util.Arrays.copyOfRange(c.b, c.p, c.p + n); c.p += n; return o; }
            case 3: { int n = (int) len(c, ai); String s = new String(c.b, c.p, n, StandardCharsets.UTF_8); c.p += n; return s; }
            case 4: { long n = len(c, ai); List<Object> l = new ArrayList<>(); for (long i = 0; i < n; i++) l.add(read(c)); return l; }
            case 5: { long n = len(c, ai); Map<Object, Object> m = new LinkedHashMap<>(); for (long i = 0; i < n; i++) { Object k = read(c); m.put(norm(k), read(c)); } return m; }
            case 6: { long t = len(c, ai); return new Tag(t, read(c)); }
            case 7: { if (ai == 20) return Boolean.FALSE; if (ai == 21) return Boolean.TRUE; if (ai == 22) return null;
                      if (ai == 24) { c.p++; return null; } if (ai == 25) { c.p += 2; return null; } if (ai == 26) { c.p += 4; return null; } if (ai == 27) { c.p += 8; return null; } return null; }
            default: throw new IllegalStateException("bad major " + major);
        }
    }

    // Map keys: keep Long/String comparable (byte[] keys unused in mdoc here).
    static Object norm(Object k) { return k instanceof byte[] ? new String((byte[]) k, StandardCharsets.UTF_8) : k; }

    static void skip(Cur c) {
        int ib = c.b[c.p++] & 0xff, major = ib >> 5, ai = ib & 0x1f;
        if (major == 0 || major == 1) { len(c, ai); }
        else if (major == 2 || major == 3) { c.p += (int) len(c, ai); }
        else if (major == 4) { long n = len(c, ai); for (long i = 0; i < n; i++) skip(c); }
        else if (major == 5) { long n = len(c, ai); for (long i = 0; i < 2 * n; i++) skip(c); }
        else if (major == 6) { len(c, ai); skip(c); }
        else { if (ai == 24) c.p++; else if (ai == 25) c.p += 2; else if (ai == 26) c.p += 4; else if (ai == 27) c.p += 8; }
    }

    private Cbor() {}
}