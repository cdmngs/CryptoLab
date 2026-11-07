import math
from pathlib import Path

WORDLIST_PATH = Path(__file__).resolve().parents[1] / "data" / "wordlist.txt"


def _load_wordlist():
    if not WORDLIST_PATH.exists():
        return set()
    with WORDLIST_PATH.open("r", encoding="utf-8") as handle:
        return {line.strip().lower() for line in handle if line.strip()}


def calculate_charset_size(password: str):
    has_lower = any(char.islower() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_digits = any(char.isdigit() for char in password)
    has_symbols = any(not char.isalnum() for char in password)

    charset = 0
    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digits:
        charset += 10
    if has_symbols:
        charset += 32
    return charset


def _format_seconds(seconds: float):
    if seconds < 1:
        return "less than 1 second"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.2f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    if seconds < 31557600:
        return f"{seconds / 86400:.2f} days"
    if seconds < 3155760000:
        return f"{seconds / 31557600:.2f} years"
    return f"{seconds / 3155760000:.2f} centuries"


def analyze_entropy(password: str):
    if password is None or not str(password).strip():
        raise ValueError("Password is required.")

    password = str(password)
    charset_size = calculate_charset_size(password)
    length = len(password)
    entropy_bits = length * math.log2(charset_size) if charset_size > 0 else 0.0
    wordlist = _load_wordlist()
    is_common_password = password.lower() in wordlist

    speeds = {
        "online_throttled": 10,
        "offline_fast_hash": 10_000_000_000,
        "offline_slow_hash": 10_000,
    }
    crack_time_estimates = {}
    for key, speed in speeds.items():
        seconds = (2**entropy_bits) / (2 * speed) if entropy_bits > 0 else 0.0
        crack_time_estimates[key] = _format_seconds(seconds)

    if is_common_password:
        verdict = "weak"
        score = 5
        explanation = (
            "This password appears in the common-password list, which is an immediate risk indicator. "
            "Attackers prioritize common and reused choices before attempting more expensive guesses."
        )
    elif entropy_bits < 28:
        verdict = "weak"
        score = 20
        explanation = (
            "The password has less than 28 bits of entropy, which is below the range commonly considered resilient. "
            "It can be guessed far too quickly with brute-force or dictionary techniques."
        )
    elif entropy_bits < 50:
        verdict = "moderate"
        score = 55
        explanation = (
            "The password has moderate entropy, but it remains vulnerable to offline guessing if the attacker has any computational support. "
            "It is better than a short common password, but still not ideal."
        )
    elif entropy_bits < 70:
        verdict = "strong"
        score = 80
        explanation = (
            "This password has strong entropy and would require a meaningful amount of effort to crack with offline attack tools. "
            "Its complexity is in the range typically preferred for sensitive accounts."
        )
    else:
        verdict = "strong"
        score = 95
        explanation = (
            "This password creates a high-entropy search space, making brute-force guessing an impractical method over a meaningful time window. "
            "This is considered resilient against common attack patterns."
        )

    return {
        "length": length,
        "charset_size": charset_size,
        "entropy_bits": round(entropy_bits, 2),
        "is_common_password": is_common_password,
        "crack_time_estimates": crack_time_estimates,
        "verdict": verdict,
        "score": score,
        "explanation": explanation,
    }
