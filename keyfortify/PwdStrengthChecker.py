import requests
import hashlib
import string

class PasswordStrengthChecker:
    def __init__(self, password: str, website: str):
        self.password = password
        self.website = website.lower()

        self.common_passwords = {
            "password", "pwd123", "123456", "123456789", "12345", "12345678", "qwerty", "abc123", "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon", "football", "baseball", "login", "starwars", "hello", "freedom", "whatever", "trustno1", "passw0rd", "p@ssword", "test", "guest", "root", "default", "superman", "master", "sunshine", "princess", "654321", "111111", "000000", "1q2w3e4r", "zaq12wsx"
        }

        self.website_aliases = {
            "youtube": ["yt", "ytb"],
            "facebook": ["fb"],
            "instagram": ["insta", "ig"],
            "twitter": ["tw", "x"],
            "google": ["g", "goog"]
        }
    
    def contains_website_name(self):
        if self.website in self.password.lower():
            return True

        if self.website in self.website_aliases:
            for alias in self.website_aliases[self.website]:
                if alias in self.password.lower():
                    return True
        
        return False

    def is_common_password(self):
        return self.password.lower() in self.common_passwords
    
    # Breach check via HaveIBeenPwned API
    def check_breach(self):
        sha1_pw = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_pw[:5], sha1_pw[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)

        if response.status_code != 200:
            return False, "Error checking breach database."
        
        hashes = (line.split(":") for line in response.text.splitlines())

        for h,count in hashes:
            if h == suffix:
                count = int(count)
                if count > 1000:
                    return True, f"Password found in {count} breaches (Very Weak)."
                else:
                    return True, f"Password found in {count} breaches."
            return False, "Password not found in known breaches."
        
    def estimate_crack_time(self):
        charset = 0

        if (any(c.islower()) for c in self.password): charset += 26
        if (any(c.isupper()) for c in self.password): charset += 26
        if (any(c.isdigit()) for c in self.password): charset += 10
        if (any(c in string.punctuation) for c in self.password): charset += len(string.punctuation)

        combinations = charset ** len(self.password)
        guesses_per_second = 1e9
        seconds = combinations / guesses_per_second

        if seconds < 60: 
            return f"{seconds:.2f} seconds"
        elif seconds < 3600: 
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        else:
            return f"{seconds/31536000:.2f} years"
        
    def evaluate_strength(self):
        if self.is_common_password():
            return "Very Weak"
        
        score = 0
        if len(self.password) >= 12: score += 2
        elif len(self.password) >= 8: score += 1

        if (any(c.islower()) for c in self.password): score += 1
        if (any(c.isupper()) for c in self.password): score += 1
        if (any(c.isdigit()) for c in self.password): score += 1
        if (any(c in string.punctuation) for c in self.password): score += 1

        if self.contains_website_name(): score -= 2

        breached, message = self.check_breach()
        if breached and "Very Weak" in message:
            return "Very Weak"
        
        if score <= 1:
            return "Very Weak"
        elif score <= 3:
            return "Weak"
        elif score <= 5:
            return "Moderate"
        else:
            return "Strong"