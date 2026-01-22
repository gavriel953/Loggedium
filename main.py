"""
main.py
Enhanced main script with better UX and error handling
"""

from loggedium.PwdStrengthChecker import PasswordStrengthChecker
import sys
import getpass

def print_banner():
    """Display application banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║        🔐  LOGGEDIUM — Password Strength Analyzer        ║
    ║                                                          ║
    ║             Analyze • Secure • Protect                   ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def get_password_input() -> str:
    """
    Get password input from user.
    Uses getpass for hidden input in production, regular input for debugging.
    """
    print("\n📝 Enter your password to analyze:")
    print("   (Note: Your password will not be stored or transmitted)")
    print("   (Press Ctrl+C to exit)\n")

    try: 
        password = getpass.getpass("Password: ")

        if not password:
            print("❌ Error: Password cannot be empty!")
            return None
        return password
    
    except KeyboardInterrupt:
        print("\n\n👋 Exiting... Stay secure!")
        sys.exit(0)

    except EOFError:
        print("\n\n❌ Error: Input terminated unexpectedly.")
        print("Please try again or press Ctrl+C to exit.")
        return None
    
    except Exception as e:
        print(f"\n❌ Unexpected error while reading password: {str(e)}")
        print("Please try again or press Ctrl+C to exit.")
        return None

def get_website_input() -> str:
    """Get website/service name or URL from user."""
    print("\n🌐 Enter the website/service (optional):")
    print("   You can enter:")
    print("     • Full URL: https://www.google.com")
    print("     • Domain: facebook.com")
    print("     • Name: twitter")
    print()

    try:
        website = input("Website/URL: ").strip()
        return website
    
    except KeyboardInterrupt:
        print("\n\n👋 Exiting... Stay secure!")
        sys.exit(0)
    
    except EOFError:
        print("\n❌ Input terminated unexpectedly.")
        return ""
    
    except Exception as e:
        print(f"\n❌ Error reading website input: {str(e)}")
        return ""
    
def display_quick_tips():
    """Display quick password security tips."""
    tips = """
    
    💡 Quick Tips for Strong Passwords:
    ═══════════════════════════════════════════════════════════
    
    ✅ DO:
       • Use 12+ characters (longer is better)
       • Mix uppercase, lowercase, numbers, and symbols
       • Use a unique password for each account
       • Consider using a passphrase (e.g., "Coffee-Morning-Piano!42")
       • Use a password manager to store passwords securely
    
    ❌ DON'T:
       • Use personal information (name, birthday, etc.)
       • Use common words or patterns
       • Reuse passwords across multiple accounts
       • Include the website name in the password
       • Use sequential or repeated characters
    
    ═══════════════════════════════════════════════════════════
    """
    print(tips)

def main():
    """Main application entry point."""
    try:
        print_banner()

        password = None
        while password is None:
            password = get_password_input()
            if password is None:
                retry = input("\n🔄 Try again? (y/n): ").strip().lower()
                if retry not in ['y', 'yes']:
                    print("\n👋 Exiting... Stay secure!")
                    return
        
        website = get_website_input()

        print("\n🔍 Analyzing password security...\n")
        checker = PasswordStrengthChecker(password, website)

        report = checker.generate_report()
        print(report)
        
        try:
            show_tips = input("\n📚 Would you like to see password security tips? (y/n): ").strip().lower()
            if show_tips in ['y', 'yes']:
                display_quick_tips()
        except (KeyboardInterrupt, EOFError):
            pass

        try:
            another = input("\n🔄 Test another password? (y/n): ").strip().lower()
            if another in ['y', 'yes']:
                print("\n" + "="*60 + "\n")
                main()
            else:
                print("\n✨ Thank you for using Loggedium! Stay secure! 🔒")
        except (KeyboardInterrupt, EOFError):
            print("\n\n✨ Thank you for using Loggedium! Stay secure! 🔒")
    
    except KeyboardInterrupt:
        print("\n\n👋 Exiting... Stay secure!")
        sys.exit(0)

    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {str(e)}")
        print("Please try again or report this issue.")
        print("\nError details for debugging:")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()