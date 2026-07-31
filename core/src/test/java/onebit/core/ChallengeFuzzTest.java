// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/** T4 exit criterion: fuzzed malformed/over-asking challenges all refused. */
public class ChallengeFuzzTest {

    static String valid() {
        return """
        {
          "v": 1,
          "nonce": "%s",
          "origin": "https://example.com",
          "verifier_id": "%s",
          "epoch": "2026-07-11",
          "policy": {
            "predicate": "age_gte",
            "value": 18,
            "icao_root_min_version": 1,
            "attestation": {"allowlist_url": "https://x/al.json", "allowlist_hash": "ab", "tier": "A"},
            "mode_b_accepted": false
          },
          "sig": "c2ln",
          "spki": "c2ln"
        }""".formatted(java.util.Base64.getEncoder().encodeToString(new byte[32]), "ab".repeat(32));
    }

    @Test
    public void validChallengeParses() throws Exception {
        Challenge c = Challenge.parse(valid());
        assertEquals("age_gte", c.predicate);
        assertEquals(18, c.value);
        assertTrue(c.display().contains("age >= 18"));
    }

    @Test
    public void overAskingChallengesRefused() {
        String[] evil = {
            valid().replace("age_gte", "dob_disclose"),
            valid().replace("age_gte", "send_dob"),
            valid().replace("\"value\": 18", "\"value\": 18, \"disclose\": [\"dob\"]"),
            valid().replace("\"v\": 1", "\"v\": 1, \"attributes\": [\"dob\",\"name\"]"),
            valid().replace("\"value\": 18", "\"value\": 0"),
            valid().replace("\"value\": 18", "\"value\": 200"),
            valid().replace("\"value\": 18", "\"value\": 18.5"),
            valid().replace("\"tier\": \"A\"", "\"tier\": \"C\""),
            valid().replace("https://example.com", "http://example.com"),
            valid().replace("https://example.com", "https://example.com/path?q=1"),
            valid().replace("\"v\": 1", "\"v\": 2"),
            valid().replace("2026-07-11", "whenever"),
            valid().replace("\"mode_b_accepted\": false", "\"mode_b_accepted\": \"yes\""),
            "not json at all", "[]", "42",
        };
        for (String e : evil) {
            try {
                Challenge.parse(e);
                fail("accepted: " + e.substring(0, Math.min(80, e.length())));
            } catch (Challenge.RefusalException expected) { }
        }
    }

    /** Structural fuzz: every mutation of these three classes must refuse. */
    @Test
    public void mutationFuzzAllRefused() throws Exception {
        Random rnd = new Random(42);
        int refused = 0, total = 500;
        for (int i = 0; i < total; i++) {
            JsonObject root = JsonParser.parseString(valid()).getAsJsonObject();
            List<JsonObject> objects = new ArrayList<>();
            collect(root, objects);
            JsonObject target = objects.get(rnd.nextInt(objects.size()));
            List<String> keys = new ArrayList<>(target.keySet());
            String key = keys.get(rnd.nextInt(keys.size()));
            switch (rnd.nextInt(3)) {
                case 0 -> target.remove(key);                         // missing required
                case 1 -> target.addProperty("x_" + rnd.nextInt(1000), rnd.nextInt()); // unknown key
                case 2 -> {                                           // type swap
                    JsonElement old = target.get(key);
                    target.add(key, (old instanceof JsonPrimitive p && p.isNumber())
                            ? new JsonPrimitive("junk") : new JsonPrimitive(rnd.nextInt()));
                }
            }
            try {
                Challenge.parse(root.toString());
                fail("fuzz iteration " + i + " accepted: " + root);
            } catch (Challenge.RefusalException e) {
                refused++;
            }
        }
        assertEquals(total, refused);
    }

    static void collect(JsonObject o, List<JsonObject> out) {
        out.add(o);
        for (String k : o.keySet()) {
            if (o.get(k).isJsonObject()) collect(o.get(k).getAsJsonObject(), out);
        }
    }

    @Test
    public void nullifierCtxIsDeterministicAndInField() {
        var a = Nullifier.ctx("ab".repeat(32), "2026-07-11");
        var b = Nullifier.ctx("ab".repeat(32), "2026-07-11");
        var c = Nullifier.ctx("cd".repeat(32), "2026-07-11");
        var d = Nullifier.ctx("ab".repeat(32), "2026-07-12");
        assertEquals(a, b);
        assertTrue(!a.equals(c) && !a.equals(d));
        assertTrue(a.signum() > 0 && a.compareTo(Nullifier.P) < 0);
    }
}