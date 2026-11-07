import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _count_repeated_blocks(blocks):
    counts = {}
    for block in blocks:
        counts[block] = counts.get(block, 0) + 1
    repeated = sum(value - 1 for value in counts.values() if value > 1)
    return repeated, bool(repeated)


def analyze_aes_mode(plaintext: str):
    if plaintext is None or not str(plaintext):
        raise ValueError("Plaintext is required.")

    plaintext_text = str(plaintext)
    key = os.urandom(32)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext_text.encode("utf-8")) + padder.finalize()

    ecb_cipher = Cipher(algorithms.AES(key), modes.ECB())
    ecb_encryptor = ecb_cipher.encryptor()
    ecb_ciphertext = ecb_encryptor.update(padded) + ecb_encryptor.finalize()
    ecb_blocks = [ecb_ciphertext[i: i + 16] for i in range(0, len(ecb_ciphertext), 16)]
    ecb_repeated_count, ecb_pattern_leaked = _count_repeated_blocks(ecb_blocks)

    nonce = os.urandom(12)
    gcm_cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    gcm_encryptor = gcm_cipher.encryptor()
    gcm_ciphertext = gcm_encryptor.update(padded) + gcm_encryptor.finalize()
    gcm_tag = gcm_encryptor.tag
    gcm_blocks = [gcm_ciphertext[i: i + 16] for i in range(0, len(gcm_ciphertext), 16)]
    gcm_repeated_count, gcm_pattern_leaked = _count_repeated_blocks(gcm_blocks)

    verdict = "weak" if ecb_pattern_leaked else "strong"
    explanation = (
        "ECB encrypts each block independently, so identical plaintext blocks produce identical ciphertext blocks. "
        "This leaks structure and reveals repeated patterns in the underlying data. GCM uses a nonce and authentication tag, so it does not exhibit the same block-level pattern leakage even when the plaintext is repeated."
    )

    return {
        "plaintext": plaintext_text,
        "plaintext_block_count": len([plaintext_text[i: i + 16] for i in range(0, len(plaintext_text), 16)]),
        "ecb": {
            "ciphertext_hex": ecb_ciphertext.hex(),
            "block_count": len(ecb_blocks),
            "repeated_ciphertext_blocks": ecb_repeated_count,
            "pattern_leaked": ecb_pattern_leaked,
        },
        "gcm": {
            "ciphertext_hex": gcm_ciphertext.hex(),
            "nonce_hex": nonce.hex(),
            "auth_tag_hex": gcm_tag.hex(),
            "block_count": len(gcm_blocks),
            "repeated_ciphertext_blocks": gcm_repeated_count,
            "pattern_leaked": gcm_pattern_leaked,
        },
        "verdict": verdict,
        "explanation": explanation,
    }
