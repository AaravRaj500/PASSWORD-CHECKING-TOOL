import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;
import java.util.Set;


public class PasswordSecurityChecker {

    public static void main(String[] args) {
        PasswordAnalyzer analyzer = new PasswordAnalyzer(CommonPasswords.load(Path.of("common-passwords.txt")));

        
        Console console = System.console();
        Scanner scanner = (console == null) ? new Scanner(System.in) : null;

        System.out.println("=== Password Security Checker ===");
        System.out.println("Type a password to analyse it. Type 'exit' to quit.");
        if (console == null) {
            System.out.println("(No secure console found, so what you type will be visible.)");
        }
        System.out.println();

        while (true) {
            String input = readPassword(console, scanner);
            if (input == null || input.equalsIgnoreCase("exit")) {
                System.out.println("Session closed.");
                break;
            }
            printReport(analyzer.evaluate(input));
        }
    }

  
    private static String readPassword(Console console, Scanner scanner) {
        if (console != null) {
            char[] chars = console.readPassword("Enter password: ");
            if (chars == null) return null;
            try {
                return new String(chars);
            } finally {
                Arrays.fill(chars, '\0'); 
            }
        }
        System.out.print("Enter password: ");
        return scanner.hasNextLine() ? scanner.nextLine() : null;
    }

    private static void printReport(PasswordReport report) {
        System.out.println("\n[ Security Analysis ]");
        for (CheckDetail d : report.details()) {
            System.out.println((d.passed() ? "[PASS] " : "[FAIL] ") + d.criteria());
            if (!d.passed()) System.out.println("       Tip: " + d.tip());
        }
        System.out.printf("Estimated entropy: ~%.0f bits (rough guide, not a guarantee)%n", report.entropyBits());
        System.out.println("Overall strength: " + report.strength());
        System.out.println("\n");
    }
}


class PasswordAnalyzer {
    private static final int MIN_LENGTH = 12;
    private static final String[] KEYBOARD_ROWS = {"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"};

    private final Set<String> common;

    PasswordAnalyzer(Set<String> common) {
        this.common = common;
    }

    PasswordReport evaluate(String password) {
        if (password == null || password.isBlank()) {
            return new PasswordReport(Strength.CRITICAL_WEAKNESS, 0,
                    List.of(new CheckDetail("A password was entered", false, "Type at least one character.")));
        }

        boolean lower = false, upper = false, digit = false, symbol = false;
        for (char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) lower = true;
            else if (Character.isUpperCase(c)) upper = true;
            else if (Character.isDigit(c)) digit = true;
            else if (!Character.isLetter(c)) symbol = true; 
        }

        boolean lengthOk = password.length() >= MIN_LENGTH;
        boolean isCommon = isCommon(password);
        boolean hasPattern = hasRepeat(password, 3) || hasSequence(password, 4) || hasKeyboardRun(password, 4);

        List<CheckDetail> checks = new ArrayList<>();
        checks.add(new CheckDetail("Length (" + MIN_LENGTH + "+ characters)", lengthOk,
                "Longer is better. A passphrase of several random words works well."));
        checks.add(new CheckDetail("Upper and lower case letters", lower && upper,
                "Mix capital and small letters."));
        checks.add(new CheckDetail("Contains a digit and a symbol", digit && symbol,
                "Add a number and a symbol such as ! or ~ (optional if the password is very long)."));
        checks.add(new CheckDetail("Not a common or breached password", !isCommon,
                "Avoid common words, even with swaps like @ for a or 0 for o."));
        checks.add(new CheckDetail("No obvious patterns (aaa, abcd, 1234, qwer)", !hasPattern,
                "Avoid repeats, alphabet or number runs and keyboard rows."));

        double bits = estimateEntropy(password, lower, upper, digit, symbol);
        if (hasPattern) bits *= 0.6; 
        Strength strength;
        if (isCommon) strength = Strength.CRITICAL_WEAKNESS;
        else if (bits < 36) strength = Strength.WEAK;
        else if (bits < 60 || !lengthOk || hasPattern) strength = Strength.MODERATE;
        else strength = Strength.STRONG;

        return new PasswordReport(strength, isCommon ? Math.min(bits, 10) : bits, checks);
    }

    /** length * log2(size of the character pool). An upper bound: real attackers use dictionaries. */
    private static double estimateEntropy(String p, boolean lower, boolean upper, boolean digit, boolean symbol) {
        int pool = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 33 : 0);
        if (pool == 0) pool = 26;
        return p.length() * (Math.log(pool) / Math.log(2));
    }

 
    private boolean isCommon(String password) {
        String raw = password.toLowerCase(Locale.ROOT);
        
        for (String candidate : new String[]{raw, normalise(raw, 'i'), normalise(raw, 'l')}) {
            if (common.contains(candidate)) return true;
            String stripped = candidate.replaceAll("[^a-z]+$", "");
            if (!stripped.isEmpty() && common.contains(stripped)) return true;
        }
        return false;
    }

   
    private static String normalise(String s, char oneAs) {
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            sb.append(switch (c) {
                case '@', '4' -> 'a';
                case '0' -> 'o';
                case '3' -> 'e';
                case '$', '5' -> 's';
                case '7', '+' -> 't';
                case '1' -> oneAs;
                case '!', '|' -> 'i';
                default -> c;
            });
        }
        return sb.toString();
    }

   
    private static boolean hasRepeat(String p, int n) {
        String s = p.toLowerCase(Locale.ROOT);
        int run = 1;
        for (int i = 1; i < s.length(); i++) {
            run = (s.charAt(i) == s.charAt(i - 1)) ? run + 1 : 1;
            if (run >= n) return true;
        }
        return false;
    }

 
    private static boolean hasSequence(String p, int n) {
        String s = p.toLowerCase(Locale.ROOT);
        int up = 1, down = 1;
        for (int i = 1; i < s.length(); i++) {
            int diff = s.charAt(i) - s.charAt(i - 1);
            up = (diff == 1) ? up + 1 : 1;
            down = (diff == -1) ? down + 1 : 1;
            if (up >= n || down >= n) return true;
        }
        return false;
    }

    
    private static boolean hasKeyboardRun(String p, int n) {
        String s = p.toLowerCase(Locale.ROOT);
        for (String row : KEYBOARD_ROWS) {
            String reversed = new StringBuilder(row).reverse().toString();
            for (int i = 0; i + n <= row.length(); i++) {
                if (s.contains(row.substring(i, i + n)) || s.contains(reversed.substring(i, i + n))) return true;
            }
        }
        return false;
    }
}


final class CommonPasswords {
    private static final String[] BUILT_IN = {
        "password", "123456", "12345678", "123456789", "qwerty", "qwertyuiop", "abc123", "letmein",
        "admin", "administrator", "welcome", "iloveyou", "monkey", "dragon", "football", "baseball",
        "master", "login", "princess", "sunshine", "shadow", "superman", "trustno1", "111111", "000000",
        "1q2w3e4r", "zaq12wsx", "changeme", "secret", "hello", "freedom", "whatever", "qazwsx",
        "asdfgh", "root", "toor", "test", "guest", "default", "passw0rd", "p@ssword"
    };

    private CommonPasswords() {}

    static Set<String> load(Path file) {
        Set<String> set = new HashSet<>(Arrays.asList(BUILT_IN));
        if (Files.isRegularFile(file)) {
            try {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    String w = line.trim().toLowerCase(Locale.ROOT);
                    if (!w.isEmpty()) set.add(w);
                }
                System.out.println("Loaded " + set.size() + " common passwords from " + file + ".");
            } catch (IOException e) {
                System.out.println("Could not read " + file + ", using the built-in list.");
            }
        } else {
            System.out.println("Using the built-in list of " + set.size()
                    + " common passwords. Add a common-passwords.txt file for a stronger check.");
        }
        return set;
    }
}

enum Strength { CRITICAL_WEAKNESS, WEAK, MODERATE, STRONG }

record CheckDetail(String criteria, boolean passed, String tip) {}

record PasswordReport(Strength strength, double entropyBits, List<CheckDetail> details) {}
