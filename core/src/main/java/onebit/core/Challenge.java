package onebit.core;

import java.util.Base64;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

/**
 * SPEC §6.1 challenge, parsed with a whitelist-everything posture (V5):
 * unknown keys anywhere are refusal, unknown predicates are refusal, wrong
 * types are refusal. The wire format cannot express attribute disclosure;
 * anything trying is refused before any key or credential is touched.
 */
public final class Challenge {

    /** The complete predicate grammar. Extending this to attribute release
     *  is a protocol violation (V5), not a configuration. */
    public static final Set<String> GRAMMAR = Set.of("age_gte");

    public final byte[] nonce;
    public final String origin;
    public final String verifierId;
    public final String epoch;
    public final String predicate;
    public final int value;
    public final int icaoRootMinVersion;
    public final String attestationTier;
    public final boolean modeBAccepted;
    public final String sig;

    public static final class RefusalException extends Exception {
        public RefusalException(String why) { super(why); }
    }

    public static Challenge parse(String json) throws RefusalException {
        JsonObject o;
        try {
            o = JsonParser.parseString(json).getAsJsonObject();
        } catch (Exception e) {
            throw new RefusalException("not a JSON object");
        }
        requireKeys(o, Set.of("v", "nonce", "origin", "verifier_id", "epoch", "policy", "sig"), "top-level");
        if (asInt(o, "v") != 1) throw new RefusalException("unsupported version");

        byte[] nonce;
        try {
            nonce = Base64.getDecoder().decode(asString(o, "nonce"));
        } catch (IllegalArgumentException e) {
            throw new RefusalException("nonce not base64");
        }
        if (nonce.length != 32) throw new RefusalException("nonce must be 32 bytes");

        String origin = asString(o, "origin");
        if (!origin.matches("https://[a-z0-9.-]+(:[0-9]+)?")) {
            throw new RefusalException("origin must be a bare https origin");
        }
        String verifierId = asString(o, "verifier_id");
        if (!verifierId.matches("[0-9a-f]{64}")) {
            throw new RefusalException("verifier_id must be spki sha256 hex");
        }
        String epoch = asString(o, "epoch");
        if (!epoch.matches("\\d{4}-\\d{2}-\\d{2}")) {
            throw new RefusalException("epoch must be YYYY-MM-DD");
        }

        JsonObject p = asObject(o, "policy");
        requireKeys(p, Set.of("predicate", "value", "icao_root_min_version", "attestation", "mode_b_accepted"), "policy");
        String predicate = asString(p, "predicate");
        if (!GRAMMAR.contains(predicate)) {
            throw new RefusalException("predicate not in grammar: " + predicate);
        }
        int value = asInt(p, "value");
        if (value < 1 || value > 120) throw new RefusalException("value out of range");
        int minRoot = asInt(p, "icao_root_min_version");
        if (minRoot < 1) throw new RefusalException("icao_root_min_version out of range");

        JsonObject att = asObject(p, "attestation");
        requireKeys(att, Set.of("allowlist_url", "allowlist_hash", "tier"), "attestation");
        asString(att, "allowlist_url"); // type-check every field, not just the ones we read
        asString(att, "allowlist_hash");
        String tier = asString(att, "tier");
        if (!tier.equals("A") && !tier.equals("B")) throw new RefusalException("unknown attestation tier");

        JsonElement mb = p.get("mode_b_accepted");
        if (!(mb instanceof JsonPrimitive) || !((JsonPrimitive) mb).isBoolean()) {
            throw new RefusalException("mode_b_accepted must be boolean");
        }

        Challenge c = new Challenge(nonce, origin, verifierId, epoch, predicate, value,
                minRoot, tier, mb.getAsBoolean(), asString(o, "sig"));
        return c;
    }

    /** Human line shown to the holder before any auth (SPEC §6.1). */
    public String display() {
        return origin + " asks: " + predicate.replace("_gte", " >= ") + value
                + " (tier " + attestationTier + ", epoch " + epoch + ")";
    }

    private static void requireKeys(JsonObject o, Set<String> allowed, String where)
            throws RefusalException {
        for (Map.Entry<String, JsonElement> e : o.entrySet()) {
            if (!allowed.contains(e.getKey())) {
                throw new RefusalException("unknown key in " + where + ": " + e.getKey());
            }
        }
        for (String k : allowed) {
            if (!o.has(k)) throw new RefusalException("missing key in " + where + ": " + k);
        }
    }

    private static String asString(JsonObject o, String k) throws RefusalException {
        JsonElement e = o.get(k);
        if (!(e instanceof JsonPrimitive) || !((JsonPrimitive) e).isString()) {
            throw new RefusalException(k + " must be a string");
        }
        return e.getAsString();
    }

    private static int asInt(JsonObject o, String k) throws RefusalException {
        JsonElement e = o.get(k);
        if (!(e instanceof JsonPrimitive) || !((JsonPrimitive) e).isNumber()) {
            throw new RefusalException(k + " must be a number");
        }
        double d = e.getAsDouble();
        int i = (int) d;
        if (d != i) throw new RefusalException(k + " must be an integer");
        return i;
    }

    private static JsonObject asObject(JsonObject o, String k) throws RefusalException {
        JsonElement e = o.get(k);
        if (e == null || !e.isJsonObject()) throw new RefusalException(k + " must be an object");
        return e.getAsJsonObject();
    }

    private Challenge(byte[] nonce, String origin, String verifierId, String epoch,
                      String predicate, int value, int icaoRootMinVersion,
                      String attestationTier, boolean modeBAccepted, String sig) {
        this.nonce = nonce;
        this.origin = origin;
        this.verifierId = verifierId;
        this.epoch = epoch;
        this.predicate = predicate;
        this.value = value;
        this.icaoRootMinVersion = icaoRootMinVersion;
        this.attestationTier = attestationTier;
        this.modeBAccepted = modeBAccepted;
        this.sig = sig;
    }
}
