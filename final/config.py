# config.py
import sqlite3
import os
import bcrypt # Import bcrypt for password hashing

# --- IMPORTANT: Base directory for databases ---
# This will pick up the DATABASE_DIR environment variable from Render (e.g., /var/data)
# For local development, it defaults to a 'data' folder relative to config.py
DATABASE_DIR = os.getenv('DATABASE_DIR', os.path.join(os.path.dirname(__file__), 'data'))

# Ensure the database directory exists. This is crucial for both local and Render.
# Using exist_ok=True prevents FileExistsError if the directory already exists.
os.makedirs(DATABASE_DIR, exist_ok=True)
print(f"Ensured database directory exists: {DATABASE_DIR}") # For clearer logs

# Define full paths for each database file
AUTH_DB_PATH = os.path.join(DATABASE_DIR, 'auth.db')
RESULTS_DB_PATH = os.path.join(DATABASE_DIR, 'results.db')
STUDENT_DB_PATH = os.path.join(DATABASE_DIR, 'student.db')

# --- Helper to create connection with row_factory ---
def get_db_connection(db_path):
    """Establishes a connection to a SQLite database at the given path."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row # This allows accessing columns by name (e.g., row['column_name'])
    return conn

# --- Specific connection functions (using the new paths) ---
def connect_auth_db():
    return get_db_connection(AUTH_DB_PATH)

def connect_results_db(): # Renamed from connect_db/connect_result_db for clarity and consistency
    return get_db_connection(RESULTS_DB_PATH)

def connect_student_db():
    return get_db_connection(STUDENT_DB_PATH)

# --- Database Initialization Functions ---

def initialize_auth_db():
    """Initializes the authentication database with the users table."""
    conn = connect_auth_db()
    try:
        with conn: # Use 'with' statement for automatic commit/rollback and closing
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
            # Optional: Create a default admin user if none exists
            # NOTE: Your provided default admin email was 'admin@gmail.com' and password '1335'.
            # I'll keep that for consistency with your previous code, but recommend changing it.
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1;")
            if cursor.fetchone()[0] == 0:
                print("No admin user found. Creating a default admin...")
                default_admin_username = "admin"
                default_admin_email = "admin@gmail.com" # Your specified default admin email
                default_admin_password = "1335" # Your specified default admin password - CHANGE THIS IN PRODUCTION!
                hashed_password = bcrypt.hashpw(default_admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                try:
                    cursor.execute(
                        "INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
                        (default_admin_username, default_admin_email, hashed_password, 1)
                    )
                    conn.commit()
                    print("Default admin user created: admin@gmail.com / 1335 (PLEASE CHANGE THIS IMMEDIATELY!)")
                except sqlite3.IntegrityError:
                    print("Default admin email already exists (shouldn't happen if count was 0).")
                except Exception as e:
                    print(f"Error creating default admin: {e}")
    finally:
        if conn: # Ensure connection is closed even if an error occurs outside the 'with' block
            conn.close()

def initialize_results_db():
    """Initializes the results database with uploaded_pdfs and students tables."""
    conn = connect_results_db() # Use the new connect_results_db
    try:
        with conn:
            cursor = conn.cursor()
            # Create the 'uploaded_pdfs' table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS uploaded_pdfs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pdf_hash TEXT UNIQUE
                );
            """)
            # Create the 'students' table if it doesn't exist (for general student list)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    roll_number TEXT UNIQUE
                );
            """)
    finally:
        if conn:
            conn.close()

def initialize_student_db():
    """Initializes the student database. Add fixed tables here if needed."""
    conn = connect_student_db()
    try:
        with conn:
            # Tables for sections will be created dynamically by the Excel processing worker task.
            # No fixed tables to create here unless you add a global students table to this DB too.
            pass
    finally:
        if conn:
            conn.close()

def initialize_all_dbs():
    """Calls all database initialization functions."""
    print("Initializing all databases...")
    initialize_auth_db()
    initialize_results_db()
    initialize_student_db()
    print("Database initialization complete.")
