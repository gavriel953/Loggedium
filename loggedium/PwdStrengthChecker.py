import requests
import hashlib
import string
import math
import re
from typing import Tuple, Dict
from urllib.parse import urlparse

class PasswordStrengthChecker:
    """Analyzes password strength using multiple security criteria."""
    
    COMMON_PASSWORDS = {
        "password", "pwd123", "123456", "123456789", "12345", "12345678",
        "qwerty", "abc123", "letmein", "admin", "welcome", "iloveyou",
        "monkey", "dragon", "football", "baseball", "login", "starwars",
        "hello", "freedom", "whatever", "trustno1", "passw0rd", "p@ssword",
        "test", "guest", "root", "default", "superman", "master", "sunshine",
        "princess", "654321", "111111", "000000", "1q2w3e4r", "zaq12wsx"
    }
    WEBSITE_ALIASES = {
        "youtube": ["yt", "ytb"],
        "facebook": ["fb"],
        "instagram": ["insta", "ig"],
        "twitter": ["tw", "x"],
        "google": ["g", "goog"],
        "microsoft": ["ms", "msft"],
        "amazon": ["amzn"],
        "netflix": ["nflx"]
    }
    KEYBOARD_PATTERNS = [
        "qwerty", "asdfgh", "zxcvbn", "qwertz", "azerty",
        "123456", "098765", "147258", "369258"
    ]

    def __init__(self,password: str, website: str = ""):
        """
        Initialize the password checker.
        
        Args:
            password: The password to analyze
            website: Website/service name or URL (will be parsed automatically)
        """
        self.password = password
        self.original_website_input = website.strip()
        self.website = self._extract_website_name(website)
        self._analysis_cache = {}

    def _extract_website_name(self,website_input:str):
        """
        Extract the core website name from various input formats.
        
        Handles:
        - Full URLs: https://www.google.com/search -> google
        - URLs with paths: facebook.com/login -> facebook
        - Subdomains: mail.google.com -> google
        - Plain names: youtube -> youtube
        
        Args:
            website_input: User's website input (URL or name)
            
        Returns:
            Cleaned website name
        """
        if not website_input:
            return ""
        
        website_input = website_input.lower().strip()

        if "://" in website_input or website_input.startswith('www.'):
            try:
                if not website_input.startswith((('http://','https://'))):
                    website_input = "https://"+website_input

                parsed = urlparse(website_input)
                domain = parsed.netloc or parsed.path

                if domain.startswith('www.'):
                    domain = domain[4:]
                
                parts = domain.split(".")

                if len(parts) > 2:
                    skip_subdomains = {"www", "m", "mobile", "mail", "login", "accounts", "auth", "secure"}
                    filtered_parts = [p for p in parts if p not in skip_subdomains]
                    
                    if len(filtered_parts) >= 2:
                        return filtered_parts[-2]
                    
                if len(parts) >= 2:
                    return parts[-2]
                
                return domain
            
            except:
                pass
        
        if "." in website_input:
            parts = website_input.split(".")
            if parts[0] == "www":
                parts = parts[1:]
            if parts:
                return parts[0]
        
        return website_input
    
    def contains_website_name(self) -> Tuple[bool,str]:
        """
        Check if password contains website name or common aliases.
        
        Returns:
            Tuple of (contains_name, matched_term)
        """
        if not self.website:
            return False, ""
        
        pwd_lower = self.password.lower()

        if self.website in pwd_lower:
            return True, self.website
        
        if self.website in self.WEBSITE_ALIASES:
            for alias in self.WEBSITE_ALIASES[self.website]:
                if alias in pwd_lower:
                    return True, alias
                
        return False, ""
    
    def is_common_password(self) -> bool:
        """Check if password is in the common passwords list."""
        return self.password.lower() in self.COMMON_PASSWORDS
    
    def has_keyboard_pattern(self) -> bool:
        """Detect common keyboard patterns in password."""
        pwd_lower = self.password.lower()
        for pattern in self.KEYBOARD_PATTERNS:
            if pattern in pwd_lower or pattern[::-1] in pwd_lower:
                return True
        return False
    
    def has_repeated_characters(self) -> bool:
        """Check for excessive character repetition (e.g., 'aaa', '111')."""
        return bool(re.search(r'(.)\1{2,}', self.password))
    
    def has_sequential_characters(self) -> bool:
        """Detect sequential characters (abc, 123, etc.)."""
        for i in range(len(self.password) - 2):
            chars = self.password[i:i+3]
            if chars.isdigit() or chars.isalpha():
                # Check if characters are sequential
                if all(ord(chars[j+1]) - ord(chars[j]) == 1 for j in range(2)):
                    return True
                # Check reverse sequential
                if all(ord(chars[j]) - ord(chars[j+1]) == 1 for j in range(2)):
                    return True
        return False

    def check_breach(self) -> bool:
        """
        Check if password appears in known data breaches using HaveIBeenPawned API.
        Uses k-anonymity model (only sends first 5 chars of hash).
        
        Returns:
            Tuple of (is_breached, message)
        """
        try:
            sha1_pw = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_pw[:5], sha1_pw[5:]

            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)

            if response.status_code != 200:
                return False, "⚠️ Could not verify breach status (API unavailable)."
            
            hashes = (line.split(":") for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    count = int(count)
                    if count > 10000:
                        return True, f"🚨 CRITICAL: Found in {count:,} breaches!"
                    elif count > 1000:
                        return True, f"⚠️ Found in {count:,} breaches (High Risk)."
                    else:
                        return True, f"⚠️ Found in {count:,} breach(es)."
            
            return False, "✅ Not found in known breaches."
        
        except requests.exceptions.RequestException:
            return False, "⚠️ Could not verify breach status (Network error)."
        except Exception as e:
            return False, f"⚠️ Error checking breaches: {str(e)}"
        
    def calculate_entropy(self) -> float:
        """
        Calculate password entropy in bits.
        Higher entropy = more randomness = stronger password.
        """
        charset_size = 0

        if any(c.islower() for c in self.password):
            charset_size += 26
        if any(c.isupper() for c in self.password):
            charset_size += 26
        if any(c.isdigit() for c in self.password):
            charset_size += 10
        if any(c in string.punctuation for c in self.password):
            charset_size += len(string.punctuation)

        if charset_size == 0:
            return 0.0
        
        entropy = len(self.password) * math.log(charset_size)
        return round(entropy, 2)
    
    def estimate_crack_time(self) -> Dict[str, str]: 
        """
        Estimate time to crack password using different attack scenarios.
        Uses position-based calculation for more accurate estimates.
        
        Returns:
            Dictionary with different attack scenario timings
        """
        lowercase = set(string.ascii_lowercase)
        uppercase = set(string.ascii_uppercase)
        digits = set(string.digits)
        special = set(string.punctuation)

        total_breach_attempts = 0

        for i, char in enumerate(self.password):
            if char in lowercase:
                charset_size = 26
                char_position = ord(char) - ord('a')
            elif char in uppercase:
                charset_size = 26
                char_position = ord(char) - ord('A')
            elif char in digits:
                charset_size = 10
                char_position = char_position = ord(char) - ord('0')
            elif char in special:
                charset_size = len(string.punctuation)
                char_position = string.punctuation.index(char)
            else:
                charset_size = 1
                char_position = 0
            
            remaining_positions = len(self.password) - i - 1
            total_breach_attempts += char_position * (charset_size ** remaining_positions)

        total_breach_attempts += 1

        if total_breach_attempts < 100:
            total_breach_attempts = 100
        
        scenarios = {
            "online": 1e3,
            "offline_slow": 1e9,
            "offline_fast": 1e12 
        }

        results = {}

        for scenario, speed in scenarios.items():
            seconds = total_breach_attempts / speed
            results[scenario] = self._format_time(seconds)
        
        return results
    
    def _format_time(self, seconds: float) -> str:
        """Format seconds into human-readable time."""
        
        if seconds < 1:
            return "Instant"

        minute = 60
        hour = 60 * minute
        day = 24 * hour
        year = 365 * day

        if seconds < minute:
            return f"{seconds:.1f} seconds"
        elif seconds < hour:
            return f"{seconds / minute:.1f} minutes"
        elif seconds < day:
            return f"{seconds / hour:.1f} hours"
        elif seconds < year:
            return f"{seconds / day:.1f} days"

        years = seconds / year

        if years < 1_000:
            return f"{years:.1f} years"
        elif years < 1_000_000:
            return f"{years / 1_000:.1f} thousand years"
        elif years < 1_000_000_000:
            return f"{years / 1_000_000:.1f} million years"

        elif years < 13.8e9:
            return f"{years / 1_000_000_000:.1f} billion years"
        else:
            return "Longer than the age of the universe"

        
    def evaluate_strength(self) -> Dict[str, any]:
        """
        Comprehensive password strength evaluation.
        
        Returns:
            Dictionary containing:
                - rating: Overall strength rating
                - score: Numeric score (0-100)
                - issues: List of identified weaknesses
                - suggestions: List of improvement recommendations
        """
        score = 0
        max_score = 100
        issues = []
        suggestions = []

        pwd_length = len(self.password)
        
        if pwd_length < 4:
            score = 0
            issues.append("Password is critically short (less than 4 characters)")
            suggestions.append("Use at least 12 characters for adequate security")
            return self._finalize_evaluation(score, issues, suggestions)
        
        elif pwd_length < 6:
            score = 5
            issues.append("Password is too short (less than 6 characters)")
            suggestions.append("Use at least 12 characters for better security")

        elif pwd_length < 8:
            score = 15
            issues.append("Password is short (less than 8 characters)")
            suggestions.append("Use at least 12 characters for better security")
        
        elif pwd_length < 12:
            score += 20
            suggestions.append("Consider using 12+ characters")
        
        elif pwd_length < 16:
            score += 30
        
        elif pwd_length < 20:
            score += 35
        
        else:
            score += 40

        if self.is_common_password():
            score = min(score, 5) 
            issues.append("This is a commonly used password")
            suggestions.append("Use a unique password not found in common lists")
            return self._finalize_evaluation(score, issues, suggestions)
        
        breached, breach_msg = self.check_breach()
        if breached and "CRITICAL" in breach_msg:
            score = min(score, 5)
            issues.append("Password compromised in major data breaches")
            suggestions.append("URGENT: Change this password immediately!")
            return self._finalize_evaluation(score, issues, suggestions, breach_msg)
        
        variety_score = 0
        has_lower = any(c.islower() for c in self.password)
        has_upper = any(c.isupper() for c in self.password)
        has_digit = any(c.isdigit() for c in self.password)
        has_special = any(c in string.punctuation for c in self.password)

        if has_lower:
            variety_score += 10
        else:
            issues.append("No lowercase letters")
            suggestions.append("Add lowercase letters (a-z)")

        if has_upper:
            variety_score += 10
        else:
            issues.append("No uppercase letters")
            suggestions.append("Add uppercase letters (A-Z)")

        if has_digit:
            variety_score += 10
        else:
            issues.append("No numbers")
            suggestions.append("Add numbers (0-9)")
        
        if has_special:
            variety_score += 10
        else:
            issues.append("No special characters")
            suggestions.append("Add special characters (!@#$%^&*)")

        char_types = sum([has_upper, has_digit, has_lower, has_special])
        if char_types == 1:
            score = min(score, 10)
            issues.append("Password uses only one type of character")
            suggestions.append("Mix different character types for better security")
        
        score += variety_score

        if char_types == 4:
            score += 10

        if self.has_keyboard_pattern():
            score -= 20
            issues.append("Contains keyboard pattern (e.g., 'qwerty')")
            suggestions.append("Avoid keyboard patterns")
        
        if self.has_repeated_characters():
            score -= 10
            issues.append("Contains repeated characters")
            suggestions.append("Avoid repeating the same character multiple times")

        if self.has_sequential_characters():
            score -= 10
            issues.append("Contains sequential characters (e.g., 'abc', '123')")
            suggestions.append("Avoid sequential characters")
        
        contains_site, matched_term = self.contains_website_name()
        if contains_site:
            score -= 15
            issues.append(f"Contains website/service name: '{matched_term}'")
            suggestions.append("Avoid including the website name in your password")
        
        if breached:
            score -= 30
            issues.append("Password found in data breaches")
            suggestions.append("Create a new, unique password")
        
        return self._finalize_evaluation(score, issues, suggestions, breach_msg if breached else None)
    
    def _finalize_evaluation(self, score: int, issues: list, suggestions: list, breach_msg: any) -> Dict [str, any]:
        """
        Finalize the evaluation with proper score bounds and rating.
        
        Args:
            score: Current score
            issues: List of issues found
            suggestions: List of suggestions
            breach_msg: Optional breach message
            
        Returns:
            Complete evaluation dictionary
        """
        score = max(0, min(100, score))

        if score >= 80:
            rating = "Strong"
            emoji = "🟢"
        elif score >= 60:
            rating = "Moderate"
            emoji = "🟡"
        elif score >= 40:
            rating = "Weak"
            emoji = "🟠"
        elif score >= 20:
            rating = "Very Weak"
            emoji = "🔴"
        else:
            rating = "Extremely Weak"
            emoji = "🔴"

        if breach_msg is None:
            _, breach_msg = self.check_breach()
        
        return {
            "rating": f"{emoji} {rating}",
            "score": score,
            "entropy": self.calculate_entropy(),
            "issues": issues,
            "suggestions": suggestions,
            "breach_status": breach_msg
        }
    
    def generate_report(self) -> str:
        """Generate a comprehensive text report of the password analysis."""
        evaluation = self.evaluate_strength()
        crack_times = self.estimate_crack_time()

        report = []
        report.append("=" * 60)
        report.append("🔐 PASSWORD STRENGTH ANALYSIS REPORT")
        report.append("=" * 60)
        report.append("")

        if self.website:
            report.append(f"🌐 Analyzing for: {self.original_website_input}")
            report.append(f"   Detected service: {self.website}")
            report.append("")

        report.append(f"Overall Strength: {evaluation['rating']}")
        report.append(f"Security Score: {evaluation['score']}/100")
        report.append(f"Entropy: {evaluation['entropy']} bits")
        report.append("")

        report.append(f"Breach Check: {evaluation['breach_status']}")
        report.append("")

        report.append("⏱️  Estimated Crack Times:")
        report.append(f"  • Online Attack (throttled): {crack_times['online']}")
        report.append(f"  • Offline Attack (1 GPU): {crack_times['offline_slow']}")
        report.append(f"  • Offline Attack (powerful): {crack_times['offline_fast']}")
        report.append("")

        if evaluation["issues"]:
            report.append("⚠️  Issues Found:")
            for issue in evaluation["issues"]:
                report.append(f"  • {issue}")
            report.append("")
        
        if evaluation["suggestions"]:
            report.append("💡 Suggestions for Improvement:")
            for suggestion in evaluation['suggestions']:
                report.append(f"  • {suggestion}")
            report.append("")
        
        report.append("=" * 60)

        return "\n".join(report)