"""
Create or reset a god-mode admin account for the dashboard.

Usage:
    python create_admin.py <email> <password>

This is the explicit, environment-agnostic way to provision the admin used by
GET /admin/dashboard. (In production you can instead set ADMIN_EMAIL /
ADMIN_PASSWORD env vars and the account is seeded automatically on startup.)
"""

import sys
from passlib.context import CryptContext

import database as db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def main():
    if len(sys.argv) < 3:
        print("Usage: python create_admin.py <email> <password>")
        sys.exit(1)

    email = sys.argv[1].strip().lower()
    password = sys.argv[2]

    if len(password) < 8:
        print("Refusing: choose a password of at least 8 characters.")
        sys.exit(1)

    password_hash = pwd_context.hash(password)
    existing = db.get_admin_by_email(email)

    if existing:
        db.update_admin_password(email, password_hash)
        print(f"Updated password for existing admin: {email}")
    else:
        db.create_admin(email, password_hash)
        print(f"Created god-mode admin: {email}")

    print("Sign in at:  /admin/dashboard")


if __name__ == "__main__":
    main()
