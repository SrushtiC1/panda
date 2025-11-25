import os
import hashlib
import json
import sqlite3
from flask import Flask, request, send_from_directory, jsonify, render_template

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
DB_PATH = "backend/data.db"
INTEGRITY_FILE = "integrity.json"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ------------------------------------
# DATABASE INITIALIZATION
# ------------------------------------
def init_db():
    if not os.path.exists("backend"):
        os.makedirs("backend")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            sha256 TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ------------------------------------
# SAVE DATA TO DATABASE
# ------------------------------------
def save_to_db(filename, sha):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO files (filename, sha256) VALUES (?, ?)", (filename, sha))
    conn.commit()
    conn.close()

# ------------------------------------
# LOAD DATA FROM DB
# ------------------------------------
def get_from_db(filename):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT sha256 FROM files WHERE filename=?", (filename,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

# ------------------------------------
# SHA256 FUNCTION
# ------------------------------------
def compute_sha256(file_path):
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha.update(chunk)
    return sha.hexdigest()

# ------------------------------------
# ROUTES
# ------------------------------------
@app.route("/")
def home():
    return render_template("upload.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    sha_value = compute_sha256(filepath)

    # Save in DB
    save_to_db(file.filename, sha_value)

    # Save in JSON for display
    with open(INTEGRITY_FILE, "r") as f:
        data = json.load(f)
    data[file.filename] = sha_value
    with open(INTEGRITY_FILE, "w") as f:
        json.dump(data, f, indent=4)

    return jsonify({
        "message": "File uploaded",
        "filename": file.filename,
        "sha256": sha_value
    })

@app.route("/audit/<filename>", methods=["GET"])
def audit_file(filename):
    sha = get_from_db(filename)
    if not sha:
        return jsonify({"error": "File not found"}), 404

    return jsonify({"filename": filename, "sha256": sha})

@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    return send_from_directory("uploads", filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)
