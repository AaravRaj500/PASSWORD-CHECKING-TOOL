import java.util.Arrays;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

public class PasswordSecurityChecker {


 private static final Set<String> COMMON_PASSWORDS = new HashSet<>(Arrays.asList(
        "password", "123456", "12345678", "123456789", "qwerty", "password123", "admin"
    ));

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== Password Security Checker ===");
        System.out.println("Type your passwords below to get live feedback. Type 'exit' to quit.\n");

        while (true) {
            System.out.print("Enter password: ");
            String password = scanner.nextLine();

            if (password.equalsIgnoreCase("exit")) {
                System.out.println("Exiting checker...");
                break;
            }

            evaluatePassword(password);
            System.out.println("--------------------------------------------------");
        }
        
        scanner.close();
    }

    private static void evaluatePassword(String password) {
       
        boolean hasLength = password.length() >= 8; 
        boolean hasCaseMix = password.matches(".*[a-z].*") && password.matches(".*[A-Z].*")
        boolean hasNumber = password.matches(".*\\d.*");
