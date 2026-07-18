package onebit.wallet;

/**
 * JNI bridge to native barretenberg proving (libonebitprover.so). No WebView,
 * no SharedArrayBuffer, no socket — respects V1.
 */
final class NativeProver {
    static Throwable loadError;
    static {
        try {
            // libonebitprover.so DT_NEEDs libc++.so (upstream __1); both ship
            // in jniLibs/arm64-v8a.
            System.loadLibrary("onebitprover");
        } catch (Throwable t) {
            loadError = t;
        }
    }

    /** returns [public_inputs][proof] bytes; throws on prove error. */
    static native byte[] prove(String circuitJson, String witnessTxt, String g1Path, boolean lowMem);

    private NativeProver() {}
}
