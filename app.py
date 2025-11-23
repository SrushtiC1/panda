import os
import hashlib
import json
from flask import Flask, request, send_from_directory, jsonify, render_template

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

INTEGRITY_FILE = "integrity.json"

# Load integrity file or create it
if not os.path.exists(INTEGRITY_FILE):
    with open(INTEGRITY_FILE, "w") as f:
        json.dump({}, f)


def save_integrity(filename, sha_value):
    with open(INTEGRITY_FILE, "r") as f:
        data = json.load(f)

    data[filename] = sha_value

    with open(INTEGRITY_FILE, "w") as f:
        json.dump(data, f, indent=4)


def compute_sha256(file_path):
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha.update(chunk)
    return sha.hexdigest()


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

    # Save file
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # Compute SHA
    integrity = compute_sha256(file_path)

    # Save SHA to integrity.json
    save_integrity(file.filename, integrity)

    return jsonify({
        "message": "File uploaded successfully",
        "file": file.filename,
        "sha256": integrity
    })


@app.route("/audit/<filename>", methods=["GET"])
def audit_file(filename):
    if not os.path.exists(INTEGRITY_FILE):
        return jsonify({"error": "integrity.json missing"}), 500

    with open(INTEGRITY_FILE, "r") as f:
        data = json.load(f)

    if filename not in data:
        return jsonify({"error": "File not found"}), 404

    return jsonify({
        "filename": filename,
        "sha256": data[filename]
    })


@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


if __name__ == "__main__":
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    app.run(debug=True)
