# config.py
import sqlite3
import bcrypt # Import bcrypt here as well for password hashing during initial admin creation

def get_db_connection(db_name):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row # This allows accessing columns by name
    return conn

def connect_auth_db():
    return get_db_connection('auth.db')

def connect_db():
    return get_db_connection('results.db')

def connect_result_db():
    return get_db_connection('results.db')

def connect_student_db():
    return get_db_connection('student.db')

def initialize_auth_db():
    conn = connect_auth_db()
    with conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0
            );
        """)
        # Optional: Create a default admin user if one doesn't exist
        # This is very useful for initial setup
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1;")
        if cursor.fetchone()[0] == 0:
            print("No admin user found. Creating a default admin...")
            default_admin_username = "admin"
            default_admin_email = "admin@gmail.com"
            default_admin_password = "1335" # CHANGE THIS IN PRODUCTION!
            hashed_password = bcrypt.hashpw(default_admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            try:
                cursor.execute(
                    "INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
                    (default_admin_username, default_admin_email, hashed_password, 1)
                )
                conn.commit()
                print("Default admin user created: admin@example.com / admin_password (PLEASE CHANGE THIS IMMEDIATELY!)")
            except sqlite3.IntegrityError:
                print("Default admin email already exists (shouldn't happen if count was 0).")
            except Exception as e:
                print(f"Error creating default admin: {e}")
    conn.close() # Ensure connection is closed

def initialize_results_db():
    conn = connect_db() # Using connect_db for consistency with your app's usage
    with conn:
        cursor = conn.cursor()
        # Create the 'uploaded_pdfs' table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS uploaded_pdfs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pdf_hash TEXT UNIQUE
            );
        """)
        # Create the 'students' table if it doesn't exist (from process_excel_to_single_table)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                roll_number TEXT UNIQUE
            );
        """)
    conn.close()

def initialize_student_db():
    conn = connect_student_db()
    with conn:
        # Currently, your process_excel function creates tables dynamically.
        # So, no fixed tables to create here unless you add a global students table to this DB too.
        # If you intend to have other fixed tables in student.db, add them here.
        pass
    conn.close()

def initialize_all_dbs():
    initialize_auth_db()
    initialize_results_db()
    initialize_student_db()