import hashlib
import time
from pathlib import Path

import bcrypt

WORDLIST_PATH = Path(__file__).resolve().parents[1] / "data" / "wordlist.txt"


def _load_wordlist():
    if not WORDLIST_PATH.exists():
        return []
    with WORDLIST_PATH.open("r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def detect_hash_algorithm(hash_value: str):
    normalized = (hash_value or "").strip()
    if not normalized:
        return "unknown"
    lowered = normalized.lower()
    if lowered.startswith("$2a$") or lowered.startswith("$2b$") or lowered.startswith("$2y$"):
        return "bcrypt"
    if lowered.startswith("$1$"):
        return "md5crypt"
    length = len(normalized)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    if length == 128:
        return "sha512"
    return "unknown"


def _hash_string(value: str, algorithm: str) -> str:
    encoded = value.encode("utf-8")
    if algorithm == "md5":
        return hashlib.md5(encoded).hexdigest()
    if algorithm == "sha1":
        return hashlib.sha1(encoded).hexdigest()
    if algorithm == "sha256":
        return hashlib.sha256(encoded).hexdigest()
    if algorithm == "sha512":
        return hashlib.sha512(encoded).hexdigest()
    raise ValueError(f"Unsupported fast hash algorithm: {algorithm}")


def _run_fast_hash_attack(hash_value: str, algorithm: str, wordlist):
    start = time.perf_counter()
    attempts = 0
    for word in wordlist:
        attempts += 1
        candidate = word.strip()
        if _hash_string(candidate, algorithm) == hash_value.lower():
            elapsed = time.perf_counter() - start
            return True, candidate, attempts, elapsed
    elapsed = time.perf_counter() - start
    return False, None, attempts, elapsed


def _run_bcrypt_attack(hash_value: str, wordlist):
    candidates = wordlist[:25]
    start = time.perf_counter()
    attempts = 0
    for word in candidates:
        attempts += 1
        if bcrypt.checkpw(word.encode("utf-8"), hash_value.encode("utf-8")):
            elapsed = time.perf_counter() - start
            return True, word, attempts, elapsed
    elapsed = time.perf_counter() - start
    return False, None, attempts, elapsed


def crack_hash(hash_value: str):
    normalized = (hash_value or "").strip()
    if not normalized:
        raise ValueError("Hash value is required.")

    algorithm = detect_hash_algorithm(normalized)
    wordlist = _load_wordlist()

    if algorithm in {"md5", "sha1", "sha256", "sha512"}:
        cracked, plaintext, attempts, elapsed = _run_fast_hash_attack(normalized.lower(), algorithm, wordlist)
        if cracked:
            verdict = "weak"
            score = 10
            explanation = (
                f"The hash matches a common dictionary word in the provided wordlist. "
                f"{algorithm.upper()} is fast to compute, so a short dictionary attack was sufficient to recover the plaintext '{plaintext}'."
            )
        else:
            verdict = "moderate"
            score = 50
            explanation = (
                f"This {algorithm.upper()} hash was not recovered from the small dictionary list. "
                "That means it is not immediately cracked here, but the algorithm is still fast enough that an attacker with a larger wordlist or GPU could break weak passwords quickly."
            )
        return {
            "input_hash": normalized,
            "algorithm": algorithm,
            "cracked": cracked,
            "plaintext": plaintext,
            "attempts": attempts,
            "time_seconds": round(elapsed, 6),
            "verdict": verdict,
            "score": score,
            "explanation": explanation,
        }

    if algorithm == "bcrypt":
        cracked, plaintext, attempts, elapsed = _run_bcrypt_attack(normalized, wordlist)
        if cracked:
            verdict = "weak"
            score = 20
            explanation = (
                "The password was recovered from a limited bcrypt dictionary check. "
                "Even though bcrypt is intentionally slow, a weak password still falls quickly to a targeted attack if it is in a common list."
            )
        else:
            verdict = "strong"
            score = 90
            explanation = (
                "This value was not cracked in a limited bcrypt dictionary check. "
                "bcrypt is intentionally slow and resistant to offline guessing, so a weak password is still not trivial to recover when it is not in the tested list."
            )
        return {
            "input_hash": normalized,
            "algorithm": algorithm,
            "cracked": cracked,
            "plaintext": plaintext,
            "attempts": attempts,
            "time_seconds": round(elapsed, 6),
            "verdict": verdict,
            "score": score,
            "explanation": explanation,
        }

    return {
        "input_hash": normalized,
        "algorithm": algorithm,
        "cracked": False,
        "plaintext": None,
        "attempts": 0,
        "time_seconds": 0.0,
        "verdict": "unknown",
        "score": 0,
        "explanation": (
            "The hash format is not recognized in the supported dictionary or bcrypt checks. "
            "Without a known algorithm and a feasible cracking path, the risk level cannot be determined from this sample."
        ),
    }
