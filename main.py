from loggedium.PwdStrengthChecker import PasswordStrengthChecker


def main():
    print("🔐 Loggedium — Password Strength Analyzer\n")

    password = input("Enter password: ").strip()
    website = input("Enter website name: ").strip()

    checker = PasswordStrengthChecker(password, website)

    print("\n--- Password Analysis ---")

    breached, breach_message = checker.check_breach()
    print(f"Breach check: {breach_message}")

    print(f"Estimated crack time: {checker.estimate_crack_time()}")
    print(f"Strength rating: {checker.evaluate_strength()}")


if __name__ == "__main__":
    main()
