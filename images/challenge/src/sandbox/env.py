from .helper import PersistentStore, FileLock
import os

# Initialize persistent store
STORE_PATH = "/tmp/flask_state.pickle"
LOCK_PATH = "/tmp/flask_state.lock"
store = PersistentStore(STORE_PATH)

# Get or create session cookie name and secret key with file lock protection
with FileLock(LOCK_PATH):
    # Get or create session cookie name
    SESSION_COOKIE_NAME = store.get("session_cookie_name")
    if not SESSION_COOKIE_NAME:
        SESSION_COOKIE_NAME = f"blockchain_{os.urandom(16).hex()}"
        store.set("session_cookie_name", SESSION_COOKIE_NAME)

    # Get or create secret key
    SECRET_KEY = store.get("secret_key")
    if not SECRET_KEY:
        SECRET_KEY = os.urandom(32).hex()
        store.set("secret_key", SECRET_KEY)
