import java.util.Set;

/** Dependency-free tests. Run: javac PasswordSecurityChecker.java PasswordAnalyzerTest.java && java PasswordAnalyzerTest */
public class PasswordAnalyzerTest {
    private static int failures = 0;
    private static final PasswordAnalyzer ANALYZER = new PasswordAnalyzer(
            CommonPasswords.load(java.nio.file.Path.of("no-such-file.txt")));

    public static void main(String[] args) {
        expect("empty is critical", "", Strength.CRITICAL_WEAKNESS);
        expect("spaces only is critical", "     ", Strength.CRITICAL_WEAKNESS);
        expect("P@ssw0rd (leetspeak) is critical", "P@ssw0rd", Strength.CRITICAL_WEAKNESS);
        expect("Password1! is critical", "Password1!", Strength.CRITICAL_WEAKNESS);
        expect("qwerty12345 is critical", "qwerty12345", Strength.CRITICAL_WEAKNESS);
        expect("Aa1!aaaa (repeats) is weak", "Aa1!aaaa", Strength.WEAK);
        expect("Tr0ub4dor&3 (11 chars) is moderate", "Tr0ub4dor&3", Strength.MODERATE);
        expect("abcd1234ABCD! (sequences) is not strong", "abcd1234ABCD!", Strength.MODERATE);
        expect("hello~world9A is strong", "hello~world9A", Strength.STRONG);
        expect("long passphrase is strong", "CorrectHorseBatteryStaple", Strength.STRONG);

        boolean tilde = ANALYZER.evaluate("hello~world9A").details().get(2).passed();
        check("~ counts as a symbol", tilde);

        System.out.println(failures == 0 ? "\nAll tests passed." : "\n" + failures + " test(s) FAILED.");
        if (failures > 0) System.exit(1);
    }

    private static void expect(String name, String password, Strength expected) {
        Strength actual = ANALYZER.evaluate(password).strength();
        check(name + " (got " + actual + ")", actual == expected);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        if (!ok) failures++;
    }
}
