import os
import getpass
import base64
import sqlite3
from pathlib import Path
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
PYTHON_BIN = sys.executable
from security import hash_password


DB_FILE = "vault.db"
CONFIG_FILE = "config.py"

def ask(prompt, default=None):
    if default:
        prompt = f"{prompt} [{default}]: "
    else:
        prompt = f"{prompt}: "
    val = input(prompt).strip()
    return val or default

def main():
    print("Initial File Vault setup")
    print("-------------------------")

    # Admin password
    while True:
        pw1 = getpass.getpass("Admin password: ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Passwords do not match.")
            continue
        if len(pw1) < 8:
            print("Password too short.")
            continue
        break

    # Upload directory
    upload_root = ask("Upload directory", "./uploads")
    upload_root = os.path.abspath(upload_root)
    os.makedirs(upload_root, exist_ok=True)

    # Quota
    quota_gb = ask("Default user quota (GB)", "75")
    quota_bytes = int(quota_gb) * 1024 * 1024 * 1024
    domain = ask("Please enter your domain name eg example.com or www.example.com or if useing tailscale <devicehostname>.<tailnetname>.ts.net")
    # Host / port
    host = ask("Host", "127.0.0.1")
    port = ask("Port", "5000")

    # Master key
    master_key = base64.b64encode(os.urandom(32)).decode()

    # Write config
    with open(CONFIG_FILE, "w") as f:
        f.write(f'UPLOAD_ROOT = "{upload_root}"\n')
        f.write(f"DEFAULT_QUOTA = {quota_bytes}\n")
        f.write(f'HOST = "{host}"\n')
        f.write(f"PORT = {port}\n")
        f.write(f'MASTER_KEY = "{master_key}"\n')
        f.write(f'Domain = "{domain}"\n')
    # Initialise DB
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        approved INTEGER,
        is_admin INTEGER,
        quota INTEGER,
        used INTEGER DEFAULT 0,
        enc_key BLOB
    )
    """)

    cur.execute("""
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

    # Create admin user
    admin_pw = hash_password(pw1)
    user_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    enc_key = nonce + AESGCM(base64.b64decode(master_key)).encrypt(
        nonce, user_key, None
    )

    cur.execute("""
    INSERT INTO users
    (username,password,approved,is_admin,quota,enc_key)
    VALUES ('admin',?,?,?,?,?)
    """, (admin_pw, 1, 1, quota_bytes, enc_key))

    con.commit()
    con.close()

    print("\nSetup complete.")
    print("Run the app with:")
    print("  python app.py")

   
svc = ask("Install as systemd service? (y/n)", "n")
if svc.lower() == "y":
    service_text = f"""
[Unit]
Description=File Vault
After=network.target

[Service]
User={os.getlogin()}
WorkingDirectory={os.getcwd()}
ExecStart={PYTHON_BIN} {os.getcwd()}/app.py
Restart=always
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
""".strip()

    with open("filevault.service", "w") as f:
        f.write(service_text)

    install_script = f"""
import os
import shutil
import subprocess

SERVICE_SRC = "{os.getcwd()}/filevault.service"
SERVICE_DST = "/etc/systemd/system/filevault.service"

if os.geteuid() != 0:
    print("This script must be run as root.")
    exit(1)

shutil.copy(SERVICE_SRC, SERVICE_DST)
subprocess.run(["systemctl", "daemon-reload"], check=True)
subprocess.run(["systemctl", "enable", "filevault"], check=True)
subprocess.run(["systemctl", "start", "filevault"], check=True)

print("File Vault service installed and started.")
""".strip()

    with open("install_service.py", "w") as f:
        f.write(install_script)

    print("\nSystemd files generated.")
    print("To install the service, run:")
    print("  sudo python install_service.py")


if __name__ == "__main__":
    main()
