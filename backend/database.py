import sqlite3
from datetime import datetime
import os

DATABASE_PATH = os.path.join(os.path.dirname(__file__), "app.db")


def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Users table - stores customers from Shopify orders
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            phone TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # User Plans table - stores plans purchased by users with quantity
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sku TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            plan_title TEXT,
            total_quantity INTEGER DEFAULT 0,
            used_quantity INTEGER DEFAULT 0,
            shopify_order_id TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    # Invites table - stores invites sent via Mighty Networks
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_plan_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            mighty_invite_id TEXT,
            recipient_email TEXT NOT NULL,
            recipient_first_name TEXT,
            recipient_last_name TEXT,
            mighty_user_id INTEGER,
            status TEXT DEFAULT 'sent',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_plan_id) REFERENCES user_plans(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    conn.commit()
    conn.close()


# User functions
def create_user(email, password, first_name=None, last_name=None, phone=None):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (email, password, first_name, last_name, phone)
            VALUES (?, ?, ?, ?, ?)
        """, (email, password, first_name, last_name, phone))
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        # User already exists, return existing user
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        return row["id"] if row else None
    finally:
        conn.close()


def get_user_by_email(email):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_user_password(user_id, hashed_password):
    """Update user password with a hashed version."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users 
        SET password = ?, updated_at = ?
        WHERE id = ?
    """, (hashed_password, datetime.utcnow().isoformat(), user_id))
    conn.commit()
    conn.close()


# User Plans functions
def add_user_plan(user_id, sku, plan_id, plan_title, quantity, shopify_order_id=None):
    conn = get_connection()
    cursor = conn.cursor()
    
    # Check if user already has this plan
    cursor.execute("""
        SELECT id, total_quantity FROM user_plans 
        WHERE user_id = ? AND plan_id = ?
    """, (user_id, plan_id))
    existing = cursor.fetchone()
    
    if existing:
        # Update existing plan quantity
        new_quantity = existing["total_quantity"] + quantity
        cursor.execute("""
            UPDATE user_plans 
            SET total_quantity = ?, updated_at = ?
            WHERE id = ?
        """, (new_quantity, datetime.utcnow().isoformat(), existing["id"]))
        plan_id_result = existing["id"]
    else:
        # Create new plan entry
        cursor.execute("""
            INSERT INTO user_plans (user_id, sku, plan_id, plan_title, total_quantity, shopify_order_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, sku, plan_id, plan_title, quantity, shopify_order_id))
        plan_id_result = cursor.lastrowid
    
    conn.commit()
    conn.close()
    return plan_id_result


def get_user_plans(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM user_plans WHERE user_id = ?
    """, (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_user_plan_by_id(plan_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_plans WHERE id = ?", (plan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def increment_used_quantity(user_plan_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE user_plans 
        SET used_quantity = used_quantity + 1, updated_at = ?
        WHERE id = ?
    """, (datetime.utcnow().isoformat(), user_plan_id))
    conn.commit()
    conn.close()


def decrement_used_quantity(user_plan_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE user_plans 
        SET used_quantity = used_quantity - 1, updated_at = ?
        WHERE id = ? AND used_quantity > 0
    """, (datetime.utcnow().isoformat(), user_plan_id))
    conn.commit()
    conn.close()


# Invites functions
def create_invite(user_plan_id, user_id, mighty_invite_id, recipient_email, 
                  recipient_first_name=None, recipient_last_name=None, mighty_user_id=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO invites (user_plan_id, user_id, mighty_invite_id, recipient_email, 
                            recipient_first_name, recipient_last_name, mighty_user_id, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'sent')
    """, (user_plan_id, user_id, mighty_invite_id, recipient_email, 
          recipient_first_name, recipient_last_name, mighty_user_id))
    conn.commit()
    invite_id = cursor.lastrowid
    conn.close()
    return invite_id


def get_invites_by_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT i.*, up.plan_title, up.plan_id as mighty_plan_id
        FROM invites i
        JOIN user_plans up ON i.user_plan_id = up.id
        WHERE i.user_id = ?
        ORDER BY i.created_at DESC
    """, (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_invites_by_user_plan(user_plan_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM invites WHERE user_plan_id = ? AND status = 'sent'
    """, (user_plan_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_invite_by_id(invite_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM invites WHERE id = ?", (invite_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def revoke_invite(invite_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE invites 
        SET status = 'revoked', updated_at = ?
        WHERE id = ?
    """, (datetime.utcnow().isoformat(), invite_id))
    conn.commit()
    conn.close()


# Initialize database on import
init_db()
