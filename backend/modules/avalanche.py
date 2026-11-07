import hashlib


def _hash_bytes(data: bytes, algorithm: str):
    if algorithm == "md5":
        return hashlib.md5(data).hexdigest()
    if algorithm == "sha1":
        return hashlib.sha1(data).hexdigest()
    if algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    if algorithm == "sha512":
        return hashlib.sha512(data).hexdigest()
    raise ValueError(f"Unsupported algorithm: {algorithm}")


def analyze_avalanche(text: str, algorithm: str):
    if text is None or len(str(text)) == 0:
        raise ValueError("Text is required.")
    if algorithm not in {"md5", "sha1", "sha256", "sha512"}:
        raise ValueError("Algorithm must be one of md5, sha1, sha256, or sha512.")

    original_bytes = str(text).encode("utf-8")
    if len(original_bytes) == 0:
        raise ValueError("Text cannot be empty.")

    original_hash = _hash_bytes(original_bytes, algorithm)
    flipped_bytes = bytearray(original_bytes)
    flipped_bytes[0] ^= 1
    flipped_hash = _hash_bytes(bytes(flipped_bytes), algorithm)

    original_digest = bytes.fromhex(original_hash)
    flipped_digest = bytes.fromhex(flipped_hash)
    changed_bits = sum(bin(a ^ b).count("1") for a, b in zip(original_digest, flipped_digest))
    total_bits = len(original_digest) * 8
    percent_changed = (changed_bits / total_bits) * 100 if total_bits else 0.0
    deviation = abs(percent_changed - 50)

    if deviation <= 5:
        verdict = "strong"
        score = 90
        explanation = (
            f"The avalanche result is {percent_changed:.2f}% changed, which is extremely close to the ideal 50% behavior. "
            "This indicates the hash function distributes small input changes across the digest very effectively."
        )
    elif deviation <= 15:
        verdict = "moderate"
        score = 60
        explanation = (
            f"The avalanche result is {percent_changed:.2f}% changed, which is reasonably close to the ideal 50% behavior. "
            "The function is somewhat sensitive to input changes but not as cleanly balanced as a perfect avalanche effect."
        )
    else:
        verdict = "weak"
        score = 25
        explanation = (
            f"The avalanche result is {percent_changed:.2f}% changed, which is far from the ideal 50% behavior. "
            "When a small input difference causes a much more predictable or less randomized output, the function is less resistant to structural analysis."
        )

    return {
        "algorithm": algorithm,
        "original_input": text,
        "original_hash": original_hash,
        "flipped_hash": flipped_hash,
        "total_bits": total_bits,
        "changed_bits": changed_bits,
        "percent_changed": round(percent_changed, 2),
        "verdict": verdict,
        "score": score,
        "explanation": explanation,
    }
