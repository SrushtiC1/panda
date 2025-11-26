import os
import sqlite3
import hashlib
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, send_from_directory, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# -------------- Config --------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXT = None  # None => allow all; restrict if needed
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200 MB
PORT = int(os.environ.get("PORT", 10000))

# Admin credentials can be provided via env on first run
ENV_ADMIN_USER = os.environ.get("ADMIN_USER")
ENV_ADMIN_PASS = os.environ.get("ADMIN_PASS")

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR

# make upload folder
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -------------- DB helpers --------------
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        uploader TEXT DEFAULT 'user',
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()

    # create admin if not exists
    cur.execute("SELECT id FROM admin WHERE username='admin'")
    if cur.fetchone() is None:
        if ENV_ADMIN_USER and ENV_ADMIN_PASS:
            user = ENV_ADMIN_USER
            pwd = ENV_ADMIN_PASS
            print("Creating admin from ENV variables.")
        else:
            user = "admin"
            pwd = "admin123"
            print("WARNING: no ADMIN_USER/ADMIN_PASS set. Creating default admin: admin / admin123 (change immediately).")
        hashed = generate_password_hash(pwd)
        cur.execute("INSERT OR IGNORE INTO admin (username, password_hash) VALUES (?, ?)", (user, hashed))
        conn.commit()
    conn.close()

init_db()

# -------------- Utilities --------------
def compute_sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def allowed_file(filename):
    if ALLOWED_EXT is None:
        return True
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# -------------- Routes --------------
@app.route("/")
def upload_page():
    return render_template("upload.html")

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file part", "danger")
        return redirect(url_for("upload_page"))

    file = request.files["file"]
    if file.filename == "":
        flash("No file selected", "danger")
        return redirect(url_for("upload_page"))

    if not allowed_file(file.filename):
        flash("File type not allowed", "danger")
        return redirect(url_for("upload_page"))

    filename = secure_filename(file.filename)
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    stored_filename = f"{timestamp}__{filename}"
    stored_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)
    file.save(stored_path)

    sha = compute_sha256_file(stored_path)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO files (filename, stored_path, sha256, uploader) VALUES (?, ?, ?, ?)",
        (filename, stored_path, sha, session.get("admin", "user"))
    )
    conn.commit()
    conn.close()

    # If request was fetch/ajax, return json, otherwise redirect with flash
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"file": filename, "sha256": sha})

    flash(f"Uploaded {filename} (SHA-256: {sha})", "success")
    return redirect(url_for("upload_page"))

@app.route("/audit/<filename>", methods=["GET"])
def audit(filename):
    # find latest file with that original filename
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT sha256, uploaded_at FROM files WHERE filename=? ORDER BY uploaded_at DESC LIMIT 1", (filename,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify({"filename": filename, "sha256": row["sha256"], "uploaded_at": row["uploaded_at"]})

@app.route("/download/<int:file_id>", methods=["GET"])
def download(file_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT filename, stored_path FROM files WHERE id=?", (file_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        flash("File not found", "danger")
        return redirect(url_for("admin_dashboard"))
    # send_from_directory requires folder and filename; stored_path is absolute
    folder = os.path.dirname(row["stored_path"])
    stored_name = os.path.basename(row["stored_path"])
    return send_from_directory(folder, stored_name, as_attachment=True, download_name=row["filename"])

# -------- Admin auth --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "").strip()
        pwd = request.form.get("password", "")
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM admin WHERE username=?", (user,))
        row = cur.fetchone()
        conn.close()
        if row and check_password_hash(row["password_hash"], pwd):
            session["admin"] = user
            flash("Logged in as admin", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("admin", None)
    flash("Logged out", "info")
    return redirect(url_for("upload_page"))

@app.route("/admin")
def admin_dashboard():
    if "admin" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, filename, sha256, uploader, uploaded_at FROM files ORDER BY uploaded_at DESC")
    rows = cur.fetchall()
    conn.close()
    return render_template("admin.html", files=rows, admin=session.get("admin"))

# -------------- Run --------------
if __name__ == "__main__":
    # Use environment PORT on cloud
    port = int(os.environ.get("PORT", PORT))
    # disable debug in production; use environment FLAG if needed
    app.run(host="0.0.0.0", port=port)

