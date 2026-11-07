import json
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

try:
    from .modules.aes_mode import analyze_aes_mode
    from .modules.avalanche import analyze_avalanche
    from .modules.entropy_analyzer import analyze_entropy
    from .modules.hash_tester import crack_hash
except ImportError:  # pragma: no cover - supports direct script execution
    from modules.aes_mode import analyze_aes_mode
    from modules.avalanche import analyze_avalanche
    from modules.entropy_analyzer import analyze_entropy
    from modules.hash_tester import crack_hash

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
CORS(app)


@app.get("/")
def index():
    return send_file(FRONTEND_DIR / "index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "CryptoLab API"})


@app.post("/api/tests/hash-crack")
def hash_crack():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400
    hash_value = payload.get("hash_value")
    if hash_value is None or not isinstance(hash_value, str) or not hash_value.strip():
        return jsonify({"error": "Field 'hash_value' is required and must be a non-empty string."}), 400
    if len(hash_value.strip()) > 255:
        return jsonify({"error": "Field 'hash_value' is too long."}), 400
    try:
        result = crack_hash(hash_value)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Hash cracking failed: {str(exc)}"}), 500


@app.post("/api/tests/entropy")
def entropy():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400
    password = payload.get("password")
    if password is None or not isinstance(password, str) or not password.strip():
        return jsonify({"error": "Field 'password' is required and must be a non-empty string."}), 400
    if len(password.strip()) > 256:
        return jsonify({"error": "Field 'password' is too long."}), 400
    try:
        result = analyze_entropy(password)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Entropy analysis failed: {str(exc)}"}), 500


@app.post("/api/tests/avalanche")
def avalanche():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400
    text = payload.get("text")
    algorithm = payload.get("algorithm")
    if text is None or not isinstance(text, str) or not text:
        return jsonify({"error": "Field 'text' is required and must be a non-empty string."}), 400
    if len(text) > 5000:
        return jsonify({"error": "Field 'text' is too long."}), 400
    if algorithm is None or str(algorithm).lower() not in {"md5", "sha1", "sha256", "sha512"}:
        return jsonify({"error": "Field 'algorithm' must be one of md5, sha1, sha256, or sha512."}), 400
    try:
        result = analyze_avalanche(text, str(algorithm).lower())
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Avalanche analysis failed: {str(exc)}"}), 500


@app.post("/api/tests/aes-mode")
def aes_mode():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400
    plaintext = payload.get("plaintext")
    if plaintext is None or not isinstance(plaintext, str):
        return jsonify({"error": "Field 'plaintext' is required and must be a string."}), 400
    if len(plaintext) > 20000:
        return jsonify({"error": "Field 'plaintext' is too long."}), 400
    try:
        result = analyze_aes_mode(plaintext)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"AES mode analysis failed: {str(exc)}"}), 500


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "API endpoint not found."}), 404
    return send_file(FRONTEND_DIR / "index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
