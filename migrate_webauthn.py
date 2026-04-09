"""
WebAuthn Migration Script
Run this ONCE to add WebAuthn columns to the existing 'users' table.
Safe to re-run — skips columns that already exist.
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'edtech.db')

NEW_COLUMNS = [
    ("webauthn_passkey_id",         "TEXT"),
    ("webauthn_passkey_public_key", "TEXT"),
    ("webauthn_passkey_sign_count", "INTEGER DEFAULT 0"),
    ("has_passkey_enabled",         "BOOLEAN DEFAULT 0"),
    ("webauthn_face_id",            "TEXT"),
    ("webauthn_face_public_key",    "TEXT"),
    ("webauthn_face_sign_count",    "INTEGER DEFAULT 0"),
    ("has_face_lock_enabled",       "BOOLEAN DEFAULT 0"),
]

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database not found at: {DB_PATH}")
        print("  Start the Flask app first so db.create_all() runs, then re-run this script.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Get existing columns
    cur.execute("PRAGMA table_info(users)")
    existing = {row[1] for row in cur.fetchall()}

    added = 0
    for col_name, col_type in NEW_COLUMNS:
        if col_name not in existing:
            sql = f"ALTER TABLE users ADD COLUMN {col_name} {col_type}"
            cur.execute(sql)
            print(f"  [+] Added column: {col_name} ({col_type})")
            added += 1
        else:
            print(f"  [=] Already exists: {col_name}")

    conn.commit()
    conn.close()

    if added:
        print(f"\n[OK] Migration complete. {added} column(s) added.")
    else:
        print("\n[OK] Database already up-to-date. No changes needed.")

if __name__ == '__main__':
    migrate()
