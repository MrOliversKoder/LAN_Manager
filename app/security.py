"""Encryption key handling, PIN verification, credentials lock and CSRF protection."""
import hashlib
import hmac
import logging
import os
import secrets
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import abort, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from . import config, settings as S

log = logging.getLogger(__name__)
_fernet = None


def load_key():
    """Key order: LAN_ENCRYPTION_KEY env -> LAN_ENCRYPTION_KEY_FILE (e.g. Docker secret)
    -> auto-generated file next to the database (convenient, but see README)."""
    global _fernet
    key = os.environ.get("LAN_ENCRYPTION_KEY", "").strip()
    if not key:
        key_file = os.environ.get("LAN_ENCRYPTION_KEY_FILE")
        path = Path(key_file) if key_file else config.DATA_DIR / "encryption.key"
        if path.exists():
            key = path.read_text().strip()
        elif key_file:
            raise SystemExit(f"LAN_ENCRYPTION_KEY_FILE={key_file} does not exist")
        else:
            key = Fernet.generate_key().decode()
            path.write_text(key)
            os.chmod(path, 0o600)
            log.warning("No LAN_ENCRYPTION_KEY set: generated a key file at %s. Back it up separately "
                        "from the database, or set LAN_ENCRYPTION_KEY instead.", path)
    try:
        _fernet = Fernet(key.encode())
    except ValueError:
        raise SystemExit("LAN_ENCRYPTION_KEY is invalid. Generate one with: "
                         "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'")
    return key


def session_secret(key):
    return hashlib.sha256(b"lan-manager-session:" + key.encode()).hexdigest()


def encrypt(plain):
    return _fernet.encrypt(plain.encode()).decode() if plain else ""


def decrypt(token):
    if not token:
        return ""
    try:
        return _fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        log.error("A stored password could not be decrypted (wrong encryption key?)")
        return None


# ---- PIN -------------------------------------------------------------------
_fails = {"count": 0, "until": 0.0}


def pin_is_set():
    return bool(S.get("pin_hash"))


def set_pin(pin):
    S.set_many({"pin_hash": generate_password_hash(pin)})


def verify_pin(pin):
    """Returns (ok, message). Simple lockout after 5 wrong attempts."""
    now = time.time()
    if now < _fails["until"]:
        return False, f"Too many attempts. Try again in {int(_fails['until'] - now) + 1} seconds."
    if check_password_hash(S.get("pin_hash"), pin):
        _fails.update(count=0, until=0.0)
        return True, ""
    _fails["count"] += 1
    if _fails["count"] >= 5:
        _fails.update(count=0, until=now + 60)
        log.warning("Five wrong PIN attempts; credentials locked for 60 seconds")
    return False, "Wrong PIN."


def unlock():
    session["cred_ts"] = time.time()


def lock():
    session.pop("cred_ts", None)


def touch():
    if "cred_ts" in session:
        session["cred_ts"] = time.time()


def is_unlocked():
    ts = session.get("cred_ts")
    if not ts or not pin_is_set():
        return False
    minutes = S.get_int("cred_lock_minutes")
    return minutes <= 0 or time.time() - ts < minutes * 60


# ---- CSRF ------------------------------------------------------------------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf") or request.headers.get("X-CSRF") or ""
        if not hmac.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token. Reload the page and try again.")
