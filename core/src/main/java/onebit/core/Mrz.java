package onebit.core;

import java.time.LocalDate;

/**
 * MRZ date semantics, SPEC §3.1. One rule, one implementation; the ZK circuit
 * must implement the identical rule (divergence = soundness bug).
 *
 * Century rule for YYMMDD: YY > (currentYY + 10) -> 19YY else 20YY,
 * where currentYY comes from the check date T. Applied uniformly to DOB and
 * expiry: a 19YY-resolved expiry simply fails the notExpired predicate, which
 * is fail-closed (V6).
 */
public final class Mrz {
    private Mrz() {}

    public static LocalDate resolve(String yymmdd, LocalDate t) {
        if (yymmdd == null || !yymmdd.matches("\\d{6}")) {
            throw new IllegalArgumentException("not YYMMDD: " + yymmdd);
        }
        int yy = Integer.parseInt(yymmdd.substring(0, 2));
        int mm = Integer.parseInt(yymmdd.substring(2, 4));
        int dd = Integer.parseInt(yymmdd.substring(4, 6));
        int currentYY = t.getYear() % 100;
        int century = yy > currentYY + 10 ? 1900 : 2000;
        return LocalDate.of(century + yy, mm, dd);
    }

    /** Predicate: holder born on dobYYMMDD is at least {@code years} old at T. */
    public static boolean ageGte(String dobYYMMDD, LocalDate t, int years) {
        return !resolve(dobYYMMDD, t).plusYears(years).isAfter(t);
    }

    /** Predicate: document expiry expYYMMDD is on or after T. */
    public static boolean notExpired(String expYYMMDD, LocalDate t) {
        return !resolve(expYYMMDD, t).isBefore(t);
    }
}
