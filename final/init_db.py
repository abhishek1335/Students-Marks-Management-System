import sqlite3
import os

# Database file names
AUTH_DB = "auth.sqlite"
RESULT_DB = "college_results.sqlite"
STUDENT_DB = "student_db.sqlite"

def create_auth_db():
    conn = sqlite3.connect(AUTH_DB)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        reset_token TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Insert admin if not exists
    cursor.execute("""
    INSERT OR IGNORE INTO users (id, username, email, password, is_admin)
    VALUES (1, 'admin', 'admin@gmail.com', 
    '$2b$12$2ky8kSXg8S1SDm06EVxEc.0wu0QNeAYhtJvSvA67p9Q5wpBD4fA0O', 1)
    """)  # This password is already hashed

    conn.commit()
    conn.close()
    print("✅ auth_db.sqlite created with users table.")

def create_result_db():
    conn = sqlite3.connect(RESULT_DB)
    cursor = conn.cursor()

    # Create a table to store uploaded PDF hashes
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS uploaded_pdfs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pdf_hash TEXT UNIQUE
    )
    """)

    # Create a common student table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        roll_number TEXT UNIQUE
    )
    """)

    conn.commit()
    conn.close()
    print("✅ college_results.sqlite created with uploaded_pdfs and students tables.")

def create_student_db():
    conn = sqlite3.connect(STUDENT_DB)
    # Tables will be created dynamically based on Excel sheets
    conn.close()
    print("✅ student_db.sqlite created (tables added dynamically).")

def main():
    create_auth_db()
    create_result_db()
    create_student_db()
    print("✅ All SQLite databases initialized.")

if __name__ == "__main__":
    main()
