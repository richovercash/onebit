package onebit.wallet;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * T1 exit criterion / V1: zero network I/O. The manifest must never request
 * INTERNET (or any network-adjacent) permission — the OS then enforces the
 * invariant at the syscall boundary, stronger than any runtime assertion.
 */
public class ManifestNoNetworkTest {

    @Test
    public void manifestRequestsNoNetworkPermissions() throws Exception {
        String manifest = new String(Files.readAllBytes(
                Paths.get("src/main/AndroidManifest.xml")));
        assertTrue("manifest readable", manifest.contains("<manifest"));
        assertFalse("INTERNET must not be requested",
                manifest.contains("android.permission.INTERNET"));
        assertFalse("ACCESS_NETWORK_STATE must not be requested",
                manifest.contains("android.permission.ACCESS_NETWORK_STATE"));
    }
}
