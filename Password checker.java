import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Pattern;

public class PasswordSecurityChecker {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        PasswordAnalyzer analyzer = new PasswordAnalyzer();

        System.out.println("=== Enterprise Password Security Checker ===");
        System.out.println("Type your passwords below to get live feedback. Type 'exit' to quit.\n");

        while (true) {
            System.out.print("Enter password: ");
            String input = scanner.nextLine();

            if ("exit".equalsIgnoreCase(input != null ? input.trim() : "")) {
                System.out.println("Terminating session...");
                break;
            }

            PasswordReport report = analyzer.evaluate(input);
            printReport(report);
        }
        
        scanner.close();
    }

    private static void printReport(PasswordReport report) {
        System.out.println("\n[ Security Analysis ]");
        report.details().forEach(detail -> 
            System.out.println((detail.passed() ? "✅ " : "❌ ") + detail.criteria())
        );
        System.out.println("Overall Strength: " + report.strength() + "\n");
        System.out.println("--------------------------------------------------");
    }
}

/**
 * Handles the core security validation logic independently from the user interface.
 */
class PasswordAnalyzer {
    // Pre-compiled patterns reduce performance overhead during repeated execution
    private static final Pattern LOWERCASE = Pattern.compile(".*[a-z].*");
    private static final Pattern UPPERCASE = Pattern.compile(".*[A-Z].*");
    private static final Pattern DIGIT = Pattern.compile(".*\\d.*");
    private static final Pattern SPECIAL_CHAR = Pattern.compile(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*");
    
    // Simulates a securely loaded dictionary of compromised passwords
    private static final Set<String> BREACHED_PASSWORDS = Set.of(
        "password", "123456", "12345678", "qwerty", "admin", "password123"
    );

    public PasswordReport evaluate(String password) {
        // Defensive programming: Handle null or empty inputs gracefully
        if (password == null || password.trim().isEmpty()) {
            return new PasswordReport(Strength.CRITICAL_WEAKNESS, List.of(
                new CheckDetail("Valid input provided", false)
            ));
        }

        List<CheckDetail> checks = new ArrayList<>();
        
        // 1. Length Check
        boolean lengthPassed = password.length() >= 8;
        checks.add(new CheckDetail("Length (8+ characters)", lengthPassed));

        // 2. Case Mix Check
        boolean casePassed = LOWERCASE.matcher(password).matches() && UPPERCASE.matcher(password).matches();
        checks.add(new CheckDetail("Case mix (uppercase & lowercase)", casePassed));

        // 3. Complexity Check
        boolean complexityPassed = DIGIT.matcher(password).matches() && SPECIAL_CHAR.matcher(password).matches();
        checks.add(new CheckDetail("Alphanumeric & symbol inclusion", complexityPassed));

        // 4. Dictionary Check
        boolean uniquenessPassed = !BREACHED_PASSWORDS.contains(password.toLowerCase());
        checks.add(new CheckDetail("Passes breached password dictionary check", uniquenessPassed));

        // Calculate final score
        int score = 0;
        for (CheckDetail check : checks) {
            if (check.passed()) score++;
        }

        Strength strength = switch (score) {
            case 4 -> Strength.STRONG;
            case 3 -> Strength.MODERATE;
            default -> Strength.WEAK;
        };

        return new PasswordReport(strength, checks);
    }
}

// Modern Java constructs for immutable data structures
enum Strength {
    CRITICAL_WEAKNESS, WEAK, MODERATE, STRONG
}

record CheckDetail(String criteria, boolean passed) {}
record PasswordReport(Strength strength, List<CheckDetail> details) {}
