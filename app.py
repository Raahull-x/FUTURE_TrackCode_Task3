# app.py
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import io
import os

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# Load or generate key
FERNET_KEY = os.environ.get("ENCRYPTION_KEY")
if not FERNET_KEY:
    FERNET_KEY = Fernet.generate_key().decode()
    print("Generated ENCRYPTION_KEY:", FERNET_KEY)

# Validate key inside try/except
try:
    if isinstance(FERNET_KEY, str):
        fernet = Fernet(FERNET_KEY.encode())
    else:
        fernet = Fernet(FERNET_KEY)
except Exception as e:
    raise RuntimeError(
        "Invalid ENCRYPTION_KEY. Use a valid Fernet key."
    ) from e


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


# Encrypt: returns JSON { filename, payload } where payload is base64-text token
@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    if "file" not in request.files:
        return jsonify({"error": "Missing file"}), 400

    f = request.files["file"]
    filename = secure_filename(f.filename)
    data = f.read()

    # encrypt -> bytes
    encrypted_bytes = fernet.encrypt(data)
    # payload as text (safe to include in JSON)
    encrypted_text = encrypted_bytes.decode()

    return jsonify({
        "message": "File encrypted successfully",
        "filename": filename,
        "payload": encrypted_text
    })


# Download encrypted: accepts JSON { payload, filename } and returns a file attachment
# This is useful if you want the server to return an attachment instead of client-side JS
@app.route("/download-encrypted", methods=["POST"])
def download_encrypted():
    if not request.is_json:
        return jsonify({"error": "Send JSON body"}), 400

    body = request.get_json()
    token = body.get("payload")
    filename = secure_filename(body.get("filename", "encrypted.txt"))

    if not token:
        return jsonify({"error": "Missing payload"}), 400

    # Return the token as a text file (user can store it)
    return send_file(
        io.BytesIO(token.encode()),
        as_attachment=True,
        download_name=filename + ".encrypted.txt",
        mimetype="text/plain"
    )


# Decrypt: accepts JSON { payload, filename } and returns the decrypted file as attachment
@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    if not request.is_json:
        return jsonify({"error": "Send JSON body"}), 400

    body = request.get_json()
    token = body.get("payload")
    filename = secure_filename(body.get("filename", "output.bin"))

    if not token:
        return jsonify({"error": "Missing payload"}), 400

    try:
        decrypted = fernet.decrypt(token.encode())
    except Exception as e:
        return jsonify({"error": "Decryption failed", "details": str(e)}), 400

    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream"
    )


if __name__ == "__main__":
    print("Secure File Share running at http://127.0.0.1:5000")
    app.run(debug=True)
