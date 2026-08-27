"""
server.py — Flask backend for Secure Communication Tool
────────────────────────────────────────────────────────
Install dependencies:
        pip install flask pillow pycryptodome

Run:
    python server.py

Then open your browser at:
    http://localhost:5000
"""

from flask import Flask, request, jsonify, send_from_directory
import base64, io, os, tempfile

from auth import login as auth_login, register as auth_register
from aes import encrypt, decrypt
from steganography import embed, extract as stego_extract, embed_image, extract_image
from PIL import Image

app = Flask(__name__, static_folder=".", static_url_path="")

# ── Serve the frontend ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(".", "index.html")


# ── Auth endpoints ─────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify(ok=False, msg="Please fill in all fields.")

    if auth_login(username, password):
        return jsonify(ok=True, msg="ok")
    return jsonify(ok=False, msg="Invalid username or password.")


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify(ok=False, msg="Please fill in all fields.")
    if len(password) < 4:
        return jsonify(ok=False, msg="Password must be at least 4 characters.")

    if auth_register(username, password):
        return jsonify(ok=True, msg="Account created successfully.")
    return jsonify(ok=False, msg="Username already exists.")


# ── Steganography endpoints ────────────────────────────────────────────────────

@app.route("/api/hide", methods=["POST"])
def api_hide():
    data = request.get_json()
    image_b64 = data.get("image_b64", "")
    message   = data.get("message", "").strip()
    password  = data.get("password", "")

    if not image_b64:
        return jsonify(ok=False, msg="No image provided.")
    if not message:
        return jsonify(ok=False, msg="Message cannot be empty.")
    if not password:
        return jsonify(ok=False, msg="Password cannot be empty.")

    try:
        # Decode the base64 image from the browser
        image_bytes = base64.b64decode(image_b64)
        cover_image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        # AES-encrypt the message
        encrypted = encrypt(message, password)

        # Write cover image to a temp file, run LSB embed, read result back
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_in:
            cover_image.save(tmp_in.name)
            tmp_in_path = tmp_in.name

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_out:
            tmp_out_path = tmp_out.name

        try:
            embed(tmp_in_path, encrypted, tmp_out_path)
            with open(tmp_out_path, "rb") as f:
                stego_b64 = base64.b64encode(f.read()).decode()
        finally:
            os.unlink(tmp_in_path)
            os.unlink(tmp_out_path)

        return jsonify(ok=True, msg="Message hidden successfully!", stego_b64=stego_b64)

    except ValueError as e:
        return jsonify(ok=False, msg=str(e))
    except Exception as e:
        return jsonify(ok=False, msg=f"Error: {e}")


@app.route("/api/extract", methods=["POST"])
def api_extract():
    data = request.get_json()
    image_b64 = data.get("image_b64", "")
    password  = data.get("password", "")

    if not image_b64:
        return jsonify(ok=False, msg="No image provided.")
    if not password:
        return jsonify(ok=False, msg="Password cannot be empty.")

    try:
        image_bytes = base64.b64decode(image_b64)
        stego_image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            stego_image.save(tmp.name)
            tmp_path = tmp.name

        try:
            hidden_data = stego_extract(tmp_path)
        finally:
            os.unlink(tmp_path)

        message = decrypt(hidden_data, password)
        return jsonify(ok=True, msg=message)

    except Exception:
        return jsonify(ok=False, msg="Wrong password or no hidden data found.")
    
    
@app.route("/api/hide-image", methods=["POST"])
def api_hide_image():
    data = request.get_json()

    cover_b64  = data.get("cover_b64", "")
    secret_b64 = data.get("secret_b64", "")

    # FIX: validate inputs before doing anything
    if not cover_b64:
        return jsonify(ok=False, msg="No cover image provided.")
    if not secret_b64:
        return jsonify(ok=False, msg="No secret image provided.")

    cover_path = secret_path = out_path = None  # FIX: init to None so finally is always safe
    try:
        cover  = Image.open(io.BytesIO(base64.b64decode(cover_b64))).convert("RGB")
        secret = Image.open(io.BytesIO(base64.b64decode(secret_b64))).convert("RGB")

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as c:
            cover.save(c.name)
            cover_path = c.name

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as s:
            secret.save(s.name)
            secret_path = s.name

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as o:
            out_path = o.name

        embed_image(cover_path, secret_path, out_path)

        with open(out_path, "rb") as f:
            result = base64.b64encode(f.read()).decode()

        return jsonify(ok=True, stego_b64=result)

    except ValueError as e:
        return jsonify(ok=False, msg=str(e))
    except Exception as e:
        return jsonify(ok=False, msg=f"Error: {e}")
    finally:
        # FIX: only unlink if the file was actually created
        for path in (cover_path, secret_path, out_path):
            if path and os.path.exists(path):
                os.unlink(path)

@app.route("/api/extract-image", methods=["POST"])
def api_extract_image():
    data = request.get_json()
    image_b64 = data.get("image_b64", "")

    if not image_b64:
        return jsonify(ok=False, msg="No image provided.")

    tmp_path = None  # FIX: init to None so finally is always safe
    try:
        img = Image.open(io.BytesIO(base64.b64decode(image_b64))).convert("RGB")

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            img.save(tmp.name)
            tmp_path = tmp.name

        secret_img = extract_image(tmp_path)

        buffer = io.BytesIO()
        secret_img.save(buffer, format="PNG")
        result = base64.b64encode(buffer.getvalue()).decode()

        # FIX: return is now INSIDE the try block, always reached on success
        return jsonify(ok=True, image_b64=result)

    except ValueError as e:
        # FIX: catches "No hidden image found." raised by _bits_to_image
        return jsonify(ok=False, msg=str(e))
    except Exception as e:
        return jsonify(ok=False, msg=f"Error: {e}")
    finally:
        # FIX: only unlink if the file was actually created
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
    
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json()
    image_b64 = data.get("image_b64", "")

    if not image_b64:
        return jsonify(ok=False, msg="No image provided.")

    try:
        image_bytes = base64.b64decode(image_b64)
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            image.save(tmp.name)
            tmp_path = tmp.name

        try:
            from steganography import analyze_image
            print("ANALYZE FUNCTION CALLED")
            result = analyze_image(tmp_path)
        finally:
            os.unlink(tmp_path)

        if result:
            return jsonify(ok=True, suspicious=True,  msg="⚠ Suspicious — hidden data detected in this image.")
        else:
            return jsonify(ok=True, suspicious=False, msg="✓ Clean — no hidden data detected.")

    except Exception:
        return jsonify(ok=False, msg="Analysis failed")

# ── Run ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  ✦  Secure Communication Tool")
    print("  ✦  Open your browser at: http://localhost:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
