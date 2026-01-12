import os
import time
import sqlite3
import hashlib
import secrets
import base64
import hmac
import config
if not all([
    config.UPLOAD_ROOT,
    config.DEFAULT_QUOTA,
    config.MASTER_KEY
]):
    raise RuntimeError("Config not initialised. Run setup.py first.")
from security import hash_password, check_password
from flask import (
    Flask, request, redirect, abort,
    send_file, render_template
)
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Response, stream_with_context
import mimetypes

# -------------------------------------------------
# CONFIG
# -------------------------------------------------


DB_FILE = "vault.db"
UPLOAD_ROOT = config.UPLOAD_ROOT
DEFAULT_QUOTA = config.DEFAULT_QUOTA
MASTER_KEY = base64.b64decode(config.MASTER_KEY)


MAX_HASH_FULL = 200 * 1024 * 1024
PARTIAL_HASH_SIZE = 20 * 1024 * 1024

if len(MASTER_KEY) != 32:
    raise RuntimeError("FILEVAULT_MASTER_KEY must be set (32 bytes base64)")

os.makedirs(UPLOAD_ROOT, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.urandom(32)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------------------------------------
# DATABASE
# -------------------------------------------------

def db():
    return sqlite3.connect(DB_FILE)

def init_db():
    with db() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            approved INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            quota INTEGER,
            used INTEGER DEFAULT 0,
            enc_key BLOB
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            filename TEXT,
            sha256 TEXT,
            randhex TEXT,
            path TEXT,
            size INTEGER,
            expires INTEGER
        )
        """)
        
init_db()

# -------------------------------------------------
# AUTH
# -------------------------------------------------

class User(UserMixin):
    def __init__(self, row):
        self.id = row[0]
        self.username = row[1]
        self.password = row[2]
        self.approved = row[3]
        self.is_admin = row[4]
        self.quota = row[5]
        self.used = row[6]
        self.enc_key = row[7]

@login_manager.user_loader
def load_user(uid):
    with db() as con:
        cur = con.execute("SELECT * FROM users WHERE id=?", (uid,))
        row = cur.fetchone()
    return User(row) if row else None

def require_admin():
    if not current_user.is_admin:
        abort(403)

# -------------------------------------------------
# HELPERS
# -------------------------------------------------

def sha256_of_file(path, limit=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        if limit:
            h.update(f.read(limit))
        else:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    return h.hexdigest()

def user_cipher(user):
    n = user.enc_key[:12]
    encrypted = user.enc_key[12:]
    key = AESGCM(MASTER_KEY).decrypt(n, encrypted, None)
    return AESGCM(key)

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.route("/embed/<sha>/<rand>/<name>")
def embed(sha, rand, name):
    with db() as con:
        cur = con.execute("""
        SELECT files.path, users.enc_key, files.size
        FROM files
        JOIN users ON files.user_id = users.id
        WHERE files.sha256=? AND files.randhex=? AND files.filename=?
        """, (sha, rand, name))
        row = cur.fetchone()

    if not row:
        abort(404)

    enc_path, enc_key_blob, size = row

    # decrypt file ONCE to a temp file
    n = enc_key_blob[:12]
    key = AESGCM(MASTER_KEY).decrypt(n, enc_key_blob[12:], None)
    cipher = AESGCM(key)

    with open(enc_path, "rb") as f:
        blob = f.read()

    pt = cipher.decrypt(blob[:12], blob[12:], None)

    tmp = f"/tmp/{secrets.token_hex(8)}"
    with open(tmp, "wb") as out:
        out.write(pt)

    range_header = request.headers.get("Range", None)
    mime = mimetypes.guess_type(name)[0] or "application/octet-stream"

    if not range_header:
        return send_file(
            tmp,
            mimetype=mime,
            as_attachment=False
        )

    # Handle Range requests
    bytes_unit, byte_range = range_header.split("=")
    start, end = byte_range.split("-")

    start = int(start)
    end = int(end) if end else size - 1
    length = end - start + 1

    def generate():
        with open(tmp, "rb") as f:
            f.seek(start)
            yield f.read(length)

    rv = Response(
        stream_with_context(generate()),
        status=206,
        mimetype=mime,
        direct_passthrough=True
    )

    rv.headers.add("Content-Range", f"bytes {start}-{end}/{size}")
    rv.headers.add("Accept-Ranges", "bytes")
    rv.headers.add("Content-Length", str(length))

    return rv

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        p = hash_password(p)



        user_key = AESGCM.generate_key(bit_length=256)
        n = os.urandom(12)
        enc_key = n + AESGCM(MASTER_KEY).encrypt(n, user_key, None)

        try:
            with db() as con:
                con.execute("""
                INSERT INTO users (username,password,quota,enc_key)
                VALUES (?,?,?,?)
                """, (u, p, DEFAULT_QUOTA, enc_key))
        except sqlite3.IntegrityError:
            return "Username exists"

        return "Registered. Await admin approval."

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with db() as con:
            cur = con.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            )
            row = cur.fetchone()

        # row layout reminder:
        # 0 id
        # 1 username
        # 2 password (hashed)
        # 3 approved
        # 4 is_admin
        # 5 quota
        # 6 used
        # 7 enc_key

        if not row:
            return "Invalid username or password", 401

        if not row[3]:
            return "Account awaiting admin approval", 403

        if not check_password(password, row[2]):
            return "Invalid username or password", 401

        login_user(User(row))
        return redirect("/")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

@app.route("/")
@login_required
def dashboard():
    percent = int(
        (current_user.used / current_user.quota) * 100
    ) if current_user.quota else 0

    with db() as con:
        rows = con.execute("""
            SELECT id, filename, size, expires
            FROM files
            WHERE user_id=?
            ORDER BY id DESC
        """, (current_user.id,)).fetchall()

    files = []
    now = int(time.time())

    for r in rows:
        files.append({
            "id": r[0],
            "filename": r[1],
            "size": human_filesize(r[2]),
            "expires": (
                "Expired"
                if r[3] and r[3] < now
                else time.strftime("%Y-%m-%d", time.localtime(r[3]))
                if r[3]
                else None
            )
        })

    return render_template(
        "dashboard.html",
        used=human_filesize(current_user.used),
        quota=human_filesize(current_user.quota),
        percent=percent,
        files=files,
        is_admin=current_user.is_admin
    )

@app.route("/file/<int:file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id):
    with db() as con:
        cur = con.execute("""
            SELECT path, size
            FROM files
            WHERE id=? AND user_id=?
        """, (file_id, current_user.id))
        row = cur.fetchone()

        if not row:
            abort(404)

        path, size = row

        # delete file from disk
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

        # delete DB entry
        con.execute(
            "DELETE FROM files WHERE id=?",
            (file_id,)
        )

        # refund quota
        con.execute(
            "UPDATE users SET used = used - ? WHERE id=?",
            (size, current_user.id)
        )

    return redirect("/")
def human_filesize(size):
    for unit in ["bytes", "KB", "MB", "GB", "TB"]:
        if size < 1024 or unit == "TB":
            return f"{size:.2f} {unit}" if unit != "bytes" else f"{size} {unit}"
        size /= 1024
@app.route("/upload", methods=["POST"])
@login_required
def upload():
    files = request.files.getlist("files")
    expiry = request.form.get("expiry")

    expires = None
    if expiry and expiry != "never":
        expires = int(time.time()) + int(expiry) * 86400

    cipher = user_cipher(current_user)

    for f in files:
        name = secure_filename(f.filename)
        if not name:
            continue

        data = f.read()
        size = len(data)

        if current_user.used + size > current_user.quota:
            abort(403)

        n = os.urandom(12)
        encrypted = n + cipher.encrypt(n, data, None)

        randhex = secrets.token_hex(16)
        user_dir = os.path.join(UPLOAD_ROOT, f"user_{current_user.id}")
        os.makedirs(user_dir, exist_ok=True)

        path = os.path.join(user_dir, randhex + ".bin")
        with open(path, "wb") as out:
            out.write(encrypted)

        sha = hashlib.sha256(
            data if size <= MAX_HASH_FULL else data[:PARTIAL_HASH_SIZE]
        ).hexdigest()

        with db() as con:
            con.execute("""
            INSERT INTO files
            (user_id,filename,sha256,randhex,path,size,expires)
            VALUES (?,?,?,?,?,?,?)
            """, (current_user.id, name, sha, randhex, path, size, expires))
            con.execute("""
            UPDATE users SET used=used+? WHERE id=?
            """, (size, current_user.id))

    return redirect("/")

@app.route("/file/<int:file_id>")
@login_required
def file_page(file_id):
    with db() as con:
        cur = con.execute("""
        SELECT * FROM files
        WHERE id=? AND user_id=?
        """, (file_id, current_user.id))
        row = cur.fetchone()

    if not row:
        abort(404)

    preview = None
    if row[2].lower().endswith(".txt"):
        cipher = user_cipher(current_user)
        with open(row[5], "rb") as f:
            blob = f.read()
        n, ct = blob[:12], blob[12:]
        preview = cipher.decrypt(n, ct, None)[:15*1024].decode(errors="replace")
    size = human_filesize(row[6])
    return render_template(
        "file.html",
        file={
    "id": row[0],
    "filename": row[2],
    "sha256": row[3],
    "size": size,
    "expires": row[7],
    "download": f"{config.Domain}/download/{row[3]}/{row[4]}/{row[2]}",
    "preview": preview
}

    )

@app.route("/download/<sha>/<rand>/<name>")
def download(sha, rand, name):
    with db() as con:
        cur = con.execute("""
        SELECT files.path, users.enc_key
        FROM files JOIN users ON files.user_id = users.id
        WHERE files.sha256=? AND files.randhex=? AND files.filename=?
        """, (sha, rand, name))
        row = cur.fetchone()

    if not row:
        abort(404)

    n = row[1][:12]
    key = AESGCM(MASTER_KEY).decrypt(n, row[1][12:], None)
    cipher = AESGCM(key)

    with open(row[0], "rb") as f:
        blob = f.read()
    pt = cipher.decrypt(blob[:12], blob[12:], None)

    tmp = f"/tmp/{secrets.token_hex(8)}"
    with open(tmp, "wb") as out:
        out.write(pt)

    return send_file(tmp, as_attachment=True, download_name=name)

@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    require_admin()

    if request.method == "POST":
        uid = request.form["user_id"]
        action = request.form["action"]
        value = request.form.get("value")

        with db() as con:
            if action == "approve":
                con.execute("UPDATE users SET approved=1 WHERE id=?", (uid,))
            elif action == "quota":
                con.execute("UPDATE users SET quota=? WHERE id=?", (value, uid))

    with db() as con:
        users = con.execute("""
        SELECT id,username,approved,quota,used FROM users
        """).fetchall()

    return render_template(
        "admin.html",
        users=[{
            "id": u[0],
            "username": u[1],
            "approved": u[2],
            "quota": u[3],
            "used": u[4]
        } for u in users]
    )

if __name__ == "__main__":
    app.run(
    host=config.HOST,
    port=config.PORT
)

