# Password Security Checker

A Java console tool that rates a password's strength and explains why. It goes beyond a simple
checklist: it catches common passwords even when disguised with leetspeak (`P@ssw0rd`), flags
repeats, alphabet or number runs and keyboard rows, and gives a rough entropy estimate.

Nothing you type is stored, logged or sent anywhere. Input is hidden when run from a real terminal.

## What it checks

| Check | Why it matters |
| --- | --- |
| Length (12+ characters) | Length is the biggest factor in resisting guessing |
| Upper and lower case | Widens the set of characters an attacker must try |
| Digit and symbol | Same, but optional for very long passphrases |
| Not a common or breached password | Leetspeak and trailing digits (`Password1!`) are undone before checking |
| No obvious patterns | Catches `aaaa`, `abcd`, `1234`, `qwer` |

Overall strength is `CRITICAL_WEAKNESS`, `WEAK`, `MODERATE` or `STRONG`. A password found in the
common list is always critical, however many boxes it ticks.

## Requirements

Java 17 or newer (`java -version` to check).

## Run

```
javac PasswordSecurityChecker.java
java PasswordSecurityChecker
```

Type `exit` (or press Ctrl+D) to quit. Run it from a terminal, not an IDE console, to get hidden input.

## Run the tests

```
javac PasswordSecurityChecker.java PasswordAnalyzerTest.java
java PasswordAnalyzerTest
```

## Example

```
Enter password: P@ssw0rd
[FAIL] Length (12+ characters)
[PASS] Upper and lower case letters
[PASS] Contains a digit and a symbol
[FAIL] Not a common or breached password
[PASS] No obvious patterns (aaa, abcd, 1234, qwer)
Estimated entropy: ~10 bits (rough guide, not a guarantee)
Overall strength: CRITICAL_WEAKNESS

Enter password: hello~world9A
[PASS] all five checks
Estimated entropy: ~85 bits (rough guide, not a guarantee)
Overall strength: STRONG
```

## Stronger common-password check

By default it uses a small built-in list. For a real check, download a larger list (for example the
top 10,000 or 100,000 passwords from the SecLists project) and save it next to the program as
`common-passwords.txt`, one password per line. It is loaded automatically.

## Limitations

- The entropy figure is an estimate. Attackers use dictionaries, so words like `hello` and `world`
  are weaker than their length suggests.
- It checks patterns and a word list. It does not check a live breach database.
- The typed password becomes a Java `String`, which cannot be wiped from memory. This is a learning
  tool, not for production password handling.
