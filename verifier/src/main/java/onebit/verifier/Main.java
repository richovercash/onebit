package onebit.verifier;

import java.nio.file.Files;
import java.nio.file.Paths;

/** CLI: java -jar verifier chain.pem nonce.bin sig.bin allowlist.json */
public final class Main {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("usage: verifier <chain.pem> <nonce.bin> <sig.bin> <allowlist.json>");
            System.exit(2);
        }
        var chain = AttestationVerifier.readChain(Files.readAllBytes(Paths.get(args[0])));
        byte[] nonce = Files.readAllBytes(Paths.get(args[1]));
        byte[] sig = Files.readAllBytes(Paths.get(args[2]));
        var allowlist = AttestationVerifier.readAllowlist(Files.readString(Paths.get(args[3])));

        try {
            var r = AttestationVerifier.verify(chain, nonce, allowlist);
            AttestationVerifier.verifyDeviceSig(chain.get(0), nonce, sig);
            System.out.println("ATTESTATION OK");
            System.out.println(r);
        } catch (Exception e) {
            System.out.println("ATTESTATION REJECTED (fail closed): " + e.getMessage());
            System.exit(1);
        }
    }

    private Main() {}
}
