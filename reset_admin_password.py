"""Reset the existing La Luna owner password without deleting restaurant data.

Run in a terminal from the project folder:
    py reset_admin_password.py        # Windows
    python3 reset_admin_password.py   # macOS / Linux

Stops active owner login sessions and backs up the SQLite database first.
"""
from __future__ import annotations

import base64
import getpass
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get('LALUNA_DB_PATH', str(ROOT / 'laluna.db'))).expanduser()


def make_password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 310000)
    return 'pbkdf2_sha256$310000$' + base64.b64encode(salt).decode() + '$' + base64.b64encode(key).decode()


def main() -> int:
    print('LA LUNA - OWNER PASSWORD RESET')
    print('Database:', DB_PATH.resolve())
    if not DB_PATH.is_file():
        print('ERROR: Database not found. Run this script in the installation folder that contains your existing laluna.db.')
        print('If this is a new installation, use START_LA_LUNA_ALL_IN_ONE.bat option 1 to create the first owner account.')
        return 1

    try:
        con = sqlite3.connect(str(DB_PATH), timeout=15)
        con.row_factory = sqlite3.Row
        try:
            owners = con.execute("SELECT id, email, active FROM staff WHERE role='owner' ORDER BY id").fetchall()
            if not owners:
                print('ERROR: No owner account found. Do not delete your database to reset a password.')
                return 1
            print('\nOwner account(s):')
            for owner in owners:
                print(' -', owner['email'], '(active)' if owner['active'] else '(disabled)')
            if len(owners) == 1:
                owner = owners[0]
            else:
                selected_email = input('Enter the owner email to reset: ').strip().lower()
                owner = next((row for row in owners if row['email'] == selected_email), None)
                if not owner:
                    print('ERROR: No owner account matches that email.')
                    return 1
            if not owner['active']:
                print('ERROR: This owner account is disabled. Ask the database administrator to review it.')
                return 1

            password = getpass.getpass('\nNew password (at least 12 characters; hidden): ')
            if len(password) < 12:
                print('ERROR: Password must be at least 12 characters long. No changes made.')
                return 1
            confirmation = getpass.getpass('Confirm new password (hidden): ')
            if password != confirmation:
                print('ERROR: Passwords do not match. No changes made.')
                return 1
            if '\x00' in password:
                print('ERROR: Password cannot contain a NUL character.')
                return 1

            # SQLite's online backup API provides a consistent snapshot, even if WAL mode is in use.
            stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
            backup_path = DB_PATH.with_name(DB_PATH.name + '.backup-' + stamp + '-' + secrets.token_hex(3) + '.sqlite3')
            with sqlite3.connect(str(backup_path)) as backup:
                con.backup(backup)
            print('\nDatabase backup created:', backup_path)

            hashed = make_password_hash(password)
            with con:
                con.execute('UPDATE staff SET password_hash=? WHERE id=?', (hashed, owner['id']))
                con.execute('DELETE FROM sessions WHERE staff_id=?', (owner['id'],))
            print('SUCCESS: Owner password updated for', owner['email'])
            print('Old owner sessions have been signed out.')
            print('Open http://127.0.0.1:8000/backoffice and sign in with this email and your new password.')
            print('Keep the database backup private: it may include orders and customer information.')
            return 0
        finally:
            con.close()
    except (sqlite3.Error, OSError) as exc:
        print('ERROR: Could not reset the password:', exc)
        return 1


if __name__ == '__main__':
    sys.exit(main())
