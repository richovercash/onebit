// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Verifies the tree builder's SPKI hashes (openssl) match Java's
 *  getPublicKey().getEncoded() hashes — the wallet's lookup key. */
public final class SpkiCheck {
    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        String tree = new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of(args[1])));
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        int rsa = 0, found = 0;
        try (InputStream in = new FileInputStream(args[0])) {
            for (Object o : cf.generateCertificates(in)) {
                X509Certificate x = (X509Certificate) o;
                if (!(x.getPublicKey() instanceof RSAPublicKey)) continue;
                if (((RSAPublicKey) x.getPublicKey()).getModulus().bitLength() > 4096) continue;
                rsa++;
                byte[] h = MessageDigest.getInstance("SHA-256").digest(x.getPublicKey().getEncoded());
                StringBuilder s = new StringBuilder();
                for (byte b : h) s.append(String.format("%02x", b));
                if (tree.contains(s.toString())) found++;
            }
        }
        System.out.println("RSA<=4096 certs (Java/BC): " + rsa + " | found in tree: " + found);
    }
    private SpkiCheck() {}
}