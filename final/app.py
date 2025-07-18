import os
import io
import bcrypt
import pandas as pd
import tabula
import hashlib
import re
import random
import string
import sqlite3
import gc # Import garbage collection module

from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, Response, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash # werkzeug.security is not used for hash/check, but ok to keep
from flask_mail import Mail, Message

# --- IMPORTANT: RQ (Redis Queue) Imports and Setup ---
from redis import Redis
from rq import Queue

# Assuming config.py is in the same directory and contains these connection functions
# Ensure config.py defines: connect_auth_db, connect_results_db, connect_student_db, initialize_all_dbs
# and the DATABASE_DIR for persistent storage.
from config import connect_auth_db, connect_results_db, connect_student_db, initialize_all_dbs, DATABASE_DIR

app = Flask(__name__)
# Use environment variable for SECRET_KEY. Crucial for production.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_that_should_be_in_env_for_production')
mail = Mail(app)

# Mail configuration - IMPORTANT: Use environment variables for sensitive info in production
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your_email@gmail.com') # Replace with your actual email in env var
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your_app_password') # Replace with your app password in env var

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# --- Define upload folders and ensure they are on the persistent disk ---
# UPLOAD_FOLDER for PDFs
UPLOAD_FOLDER = os.path.join(DATABASE_DIR, 'uploads_pdfs')
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Ensure directory exists at app startup
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# UPLOAD_FOLDER1 for Excel files
UPLOAD_FOLDER1 = os.path.join(DATABASE_DIR, 'uploads_excel')
os.makedirs(UPLOAD_FOLDER1, exist_ok=True)
app.config['UPLOAD_FOLDER1'] = UPLOAD_FOLDER1

# Set a maximum content length for uploads (e.g., 100 MB)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 # 100 MB

# --- Redis & RQ Queue Setup for Flask app ---
# This will pick up the REDIS_URL environment variable from Render
# For local development, it defaults to localhost
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
redis_conn = Redis.from_url(redis_url)
q = Queue(connection=redis_conn) # Initialize RQ queue

# --- Helper Functions ---

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def generate_token():
    """Generates a random alphanumeric token."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def generate_pdf_hash(file_path):
    """Generates SHA256 hash for the uploaded PDF."""
    # Use a chunked read for very large files to avoid loading entire file into memory
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""): # Read in 4KB chunks
            hasher.update(chunk)
    return hasher.hexdigest()

# --- Flask-Login User Class ---
class User(UserMixin):
    def __init__(self, id, username, email, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = connect_auth_db()
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, is_admin FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['email'], bool(user_data['is_admin']))
    return None

# --- Authentication Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = connect_auth_db()
        with conn:
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
                               (username, email, hashed_password, 0)) # Default new users to not admin
                conn.commit()
                flash("Account created! Please log in.", "success")
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash("Email already registered. Please use a different email.", "danger")
            except Exception as e:
                flash(f"Error creating account: {str(e)}", "danger")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = connect_auth_db()
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, password, is_admin FROM users WHERE email=?", (email,))
            user = cursor.fetchone()

        if not user:
            flash("User not found!", "danger")
            return redirect(url_for('login'))

        if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            flask_login_user = User(user['id'], user['username'], user['email'], bool(user['is_admin']))
            login_user(flask_login_user)

            session['user_id'] = user['id']
            session['is_admin'] = bool(user['is_admin'])

            print(f"Session user_id: {session.get('user_id')}")
            print(f"Session is_admin: {session.get('is_admin')}")
            flash("Login successful!", "success")
            # Redirect admin to admin_dashboard, others to general dashboard
            return redirect(url_for('admin_dashboard' if bool(user['is_admin']) else 'dashboard'))
        else:
            flash("Invalid password!", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    print(f"Session user_id: {session.get('user_id')}")
    return render_template('dashboard.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    print(f"Session user_id: {session.get('user_id')}")
    print(f"Session is_admin: {session.get('is_admin')}")
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = connect_auth_db()
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
            user = cursor.fetchone()

            if user:
                token = generate_token()
                session['reset_token'] = token
                session['reset_email'] = email

                msg = Message("Password Reset", sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f"Your password reset code is: {token}"
                try:
                    mail.send(msg)
                    flash("Check your email for the reset code!", "info")
                    return redirect(url_for('reset_password'))
                except Exception as e:
                    flash(f"Error sending email: {str(e)}", "danger")
                    print(f"Email sending error: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                flash("No account found with this email!", "danger")
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        flash("Session expired! Try again.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered_token = request.form['token']
        new_password = request.form['new_password']

        if entered_token == session.get('reset_token'):
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            conn = connect_auth_db()
            with conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_new_password, session['reset_email']))
                conn.commit()

            session.pop('reset_token', None)
            session.pop('reset_email', None)
            flash("Password reset successful! You can now log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid reset code!", "danger")
    return render_template('reset_password.html')

@app.route('/create-admin', methods=['GET', 'POST'])
@login_required
def create_admin():
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = connect_auth_db()
        with conn:
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
                               (username, email, hashed_password, 1))
                conn.commit()
                flash("New admin account created!", "success")
                return redirect(url_for('admin_dashboard'))
            except sqlite3.IntegrityError:
                flash("Email already registered for an admin. Please use a different email.", "danger")
            except Exception as e:
                flash(f"Error creating admin account: {str(e)}", "danger")
    return render_template('create_admin.html')

# --- Main Application Routes ---

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/search')
@login_required # Only logged in users can search
def search_page():
    return render_template('search.html')

@app.route('/upload_details')
@login_required # Only logged in users can upload details
def details_page():
    return render_template('upload_student_details.html')

@app.route('/upload_results')
@login_required # Only logged in users can upload results
def results_page():
    return render_template('upload_student_results.html')

# --- Background Task Definition (for Excel processing) ---
# This function processes the excel for student details (to section tables)
def process_excel_to_section_tables(excel_path):
    print(f"[{os.getpid()}] Starting Excel (sections) processing for {excel_path}...")
    try:
        df = pd.read_excel(excel_path)
        conn = connect_student_db() # Use connect_student_db as per config.py
        with conn:
            cursor = conn.cursor()
            # Assuming the Excel has columns like 'Section', 'Roll Number', 'Name'
            for section_name, section_df in df.groupby('Section'):
                # Sanitize section name for table name
                clean_section_name = re.sub(r'[^a-zA-Z0-9_]', '', section_name)
                table_name = f"section_{clean_section_name}"

                cursor.execute(f"""
                    CREATE TABLE IF NOT EXISTS `{table_name}` (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        roll_number TEXT UNIQUE NOT NULL,
                        name TEXT
                    )
                """)
                conn.commit()

                for index, row in section_df.iterrows():
                    roll_number = str(row['Roll Number']).strip()
                    name = str(row['Name']).strip()
                    if roll_number and name:
                        cursor.execute(f"""
                            INSERT OR IGNORE INTO `{table_name}` (roll_number, name)
                            VALUES (?, ?)
                        """, (roll_number, name))
                conn.commit()
        print(f"[{os.getpid()}] Excel (sections) processing complete for {excel_path}.")
        flash("Excel file for sections processed successfully!", "success") # This flash won't be seen by user, logs only
    except Exception as e:
        print(f"[{os.getpid()}] Error processing Excel for sections {excel_path}: {e}")
        import traceback
        traceback.print_exc()
        flash(f"Error processing Excel for sections: {str(e)}", "danger") # This flash won't be seen
    finally:
        if os.path.exists(excel_path):
            os.remove(excel_path) # Clean up the temporary file
            print(f"[{os.getpid()}] Cleaned up {excel_path}")
        gc.collect()

# This function processes the excel for single student details (to 'students' table in results.db)
def process_excel_to_single_students_table(excel_path):
    print(f"[{os.getpid()}] Starting Excel (single students) processing for {excel_path}...")
    try:
        df = pd.read_excel(excel_path)
        conn = connect_results_db() # Use connect_results_db as per config.py
        with conn:
            cursor = conn.cursor()
            # Ensure 'students' table exists (it should be in initialize_results_db)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    roll_number TEXT UNIQUE
                )
            """)
            conn.commit()

            # Assuming the Excel has 'Roll Number', 'Name'
            for index, row in df.iterrows():
                roll_number = str(row['Roll Number']).strip()
                name = str(row['Name']).strip()
                if roll_number and name:
                    cursor.execute("""
                        INSERT OR IGNORE INTO students (roll_number, name)
                        VALUES (?, ?)
                    """, (roll_number, name))
            conn.commit()
        print(f"[{os.getpid()}] Excel (single students) processing complete for {excel_path}.")
        flash("Excel file for single students processed successfully!", "success") # This flash won't be seen
    except Exception as e:
        print(f"[{os.getpid()}] Error processing Excel for single students {excel_path}: {e}")
        import traceback
        traceback.print_exc()
        flash(f"Error processing Excel for single students: {str(e)}", "danger") # This flash won't be seen
    finally:
        if os.path.exists(excel_path):
            os.remove(excel_path) # Clean up the temporary file
            print(f"[{os.getpid()}] Cleaned up {excel_path}")
        gc.collect()

# Uploading students details Excel (section-wise)
@app.route('/upload_student_details_excel', methods=['POST'])
@login_required
def upload_student_details_excel():
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    if 'excel_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('details_page'))

    file = request.files['excel_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('details_page'))

    if file and allowed_file(file.filename, ['xlsx', 'xls']):
        filename = secure_filename(file.filename)
        excel_path = os.path.join(app.config['UPLOAD_FOLDER1'], filename)
        file.save(excel_path)

        # Enqueue the excel processing task to the RQ queue
        q.enqueue(process_excel_to_section_tables, excel_path)
        flash('Excel file uploaded. Processing student section details in the background...', 'info')
        return redirect(url_for('details_page'))
    else:
        flash('Invalid file type. Please upload an Excel file (.xlsx or .xls).', 'danger')
        return redirect(url_for('details_page'))

# Uploading students details Excel (single student list)
@app.route('/upload_single_student_excel', methods=['POST'])
@login_required
def upload_single_student_excel():
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    if 'excel_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('details_page'))

    file = request.files['excel_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('details_page'))

    if file and allowed_file(file.filename, ['xlsx', 'xls']):
        filename = secure_filename(file.filename)
        excel_path = os.path.join(app.config['UPLOAD_FOLDER1'], filename)
        file.save(excel_path)

        # Enqueue the excel processing task to the RQ queue
        q.enqueue(process_excel_to_single_students_table, excel_path)
        flash('Excel file uploaded. Processing single student details in the background...', 'info')
        return redirect(url_for('details_page'))
    else:
        flash('Invalid file type. Please upload an Excel file (.xlsx or .xls).', 'danger')
        return redirect(url_for('details_page'))

# --- Route for PDF upload (now enqueues to worker) ---
@app.route('/upload', methods=['POST'])
@login_required # Ensure only logged-in users can upload
def upload_pdf():
    print("--- Inside /upload POST request ---")
    if 'pdf_file' not in request.files:
        flash('No file selected', 'warning')
        print("No file selected in request.")
        return redirect(url_for('results_page'))

    file = request.files['pdf_file']
    year = request.form.get('year')
    semester = request.form.get('semester')

    if file.filename == '' or not year or not semester:
        flash('Missing file, year, or semester input', 'warning')
        print("Missing file, year, or semester input.")
        return redirect(url_for('results_page'))

    if not allowed_file(file.filename, ['pdf']):
        flash('Invalid file type. Please upload a PDF file.', 'danger')
        return redirect(url_for('results_page'))

    # Sanitize table name (for logging/metadata, actual table creation is in worker)
    table_name = f"y{year}_s{semester}_results"
    table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name)

    # Generate a unique filename to prevent clashes, using hash + original name
    unique_filename = f"{hashlib.sha256(file.read()).hexdigest()}_{file.filename}"
    file.seek(0) # Reset file pointer after reading for hash
    temp_pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

    try:
        # Check if this PDF (by hash) has been uploaded before
        conn_results = connect_results_db() # Use connect_results_db from config
        with conn_results:
            cursor_results = conn_results.cursor()
            cursor_results.execute("""
            CREATE TABLE IF NOT EXISTS uploaded_pdfs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pdf_hash TEXT UNIQUE
            );
            """)
            cursor_results.execute("SELECT pdf_hash FROM uploaded_pdfs WHERE pdf_hash = ?", (hashlib.sha256(file.read()).hexdigest(),))
            file.seek(0) # Reset file pointer again after reading for hash
            if cursor_results.fetchone():
                flash("This PDF has already been uploaded. No changes made.", 'warning')
                print(f"PDF {file.filename} already uploaded (hash: {hashlib.sha256(file.read()).hexdigest()}).")
                return redirect(url_for('results_page'))

        file.save(temp_pdf_path)
        print(f"File saved to temp path: {temp_pdf_path}")

        # --- Enqueue the PDF processing task to the RQ queue ---
        # The 'process_marks_pdf_task' function MUST be in worker.py
        q.enqueue(process_marks_pdf_task, temp_pdf_path, year, semester)

        # Record that we've enqueued this PDF by its hash
        # The worker will insert the hash into uploaded_pdfs table *after* successful processing
        # This prevents the app from re-enqueueing the same PDF if the worker fails.
        # This logic is a bit tricky for robust handling. For now, let the worker handle the final insert.

        flash('PDF uploaded. Processing has started in the background...', 'info')
        print("Finished /upload POST request, task enqueued.")
        return redirect(url_for('results_page'))

    except Exception as e:
        flash(f'Error uploading PDF: {str(e)}', 'danger')
        print(f"!!! ERROR during PDF upload and enqueue: {e}")
        import traceback
        traceback.print_exc()
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path) # Clean up if something went wrong before enqueuing
        return render_template('error.html', error_message=f"Error uploading PDF: {e}"), 500


# --- Search and Display Routes ---

@app.route('/get_results', methods=['POST'])
def get_results():
    htnumber = request.form.get('htno')
    if len(str(htnumber)) != 10: # Convert to string for length check
        flash('Invalid roll number length (must be 10 digits).', 'warning')
        return redirect(url_for('search_page'))

    semester_tables = ["y1_s1_results", "y1_s2_results", "y2_s1_results", "y2_s2_results",
                        "y3_s1_results", "y3_s2_results", "y4_s1_results", "y4_s2_results"]

    student_results = {}
    sgpa_results = {}
    total_cgpa_points = 0
    total_cgpa_credits = 0

    grade_values = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "COMPLE": 0, "NIL": 0} # Added NIL

    # IMPORTANT: Use connect_results_db for results.db and connect_student_db for student.db
    conn_results = connect_results_db()
    conn_student = connect_student_db()

    student_name = "Unknown" # Initialize student_name

    try:
        with conn_results:
            with conn_student:
                cursor_results = conn_results.cursor()
                cursor_student = conn_student.cursor()

                # Fetch student name from the 'students' table in 'results.db'
                cursor_results.execute("SELECT name FROM students WHERE roll_number = ? LIMIT 1", (htnumber,))
                student_name_data = cursor_results.fetchone()
                student_name = student_name_data['name'] if student_name_data else "Unknown"

                for table in semester_tables:
                    try:
                        cursor_results.execute(f"SELECT subname, grade, credits FROM `{table}` WHERE htno = ?", (htnumber,))
                        results = cursor_results.fetchall()
                        student_results[table] = results if results else "No Data"

                        if results:
                            total_credits_semester = 0
                            total_grade_points_semester = 0

                            for row in results:
                                subname = row['subname']
                                grade = str(row['grade']).strip().upper() # Ensure grade is string and uppercase
                                credits = row['credits'] if row['credits'] is not None else 0.0

                                # Attempt to fetch actual credits if current credits are zero or grade is non-passing
                                if grade in ("F", "MP", "ABSENT", "COMPLE", "NIL") or credits == 0.0:
                                    try:
                                        # Query to find a valid credit for this subject from any record (assuming credits are same per subject)
                                        cursor_results.execute(
                                            f"SELECT credits FROM `{table}` WHERE subname = ? AND credits > 0 LIMIT 1",
                                            (subname,)
                                        )
                                        fetched_credit_data = cursor_results.fetchone()
                                        if fetched_credit_data and fetched_credit_data['credits'] is not None:
                                            credits = fetched_credit_data['credits']
                                        else:
                                            credits = 0 # Default if no valid credits found
                                    except sqlite3.Error as fetch_error:
                                        print(f"Error fetching credits for {subname}: {fetch_error}")
                                        credits = 0

                                grade_point = grade_values.get(grade, 0)
                                total_credits_semester += credits
                                total_grade_points_semester += grade_point * credits

                            if total_credits_semester > 0:
                                sgpa_results[table] = round(total_grade_points_semester / total_credits_semester, 2)
                            else:
                                sgpa_results[table] = "No SGPA (No valid credits for semester)"

                            # Update CGPA calculation using semester totals
                            if total_credits_semester > 0:
                                total_cgpa_points += total_grade_points_semester
                                total_cgpa_credits += total_credits_semester
                        else:
                            sgpa_results[table] = "No Data"

                    except sqlite3.OperationalError:
                        print(f"Skipping missing table {table} for roll number {htnumber}")
                        student_results[table] = "No Data"
                        sgpa_results[table] = "No Data"
                    except Exception as e:
                        print(f"Error in {table} processing for {htnumber}: {e}")
                        student_results[table] = "Error"
                        sgpa_results[table] = "Error"

        cgpa = round(total_cgpa_points / total_cgpa_credits, 2) if total_cgpa_credits > 0 else "No CGPA"

    except Exception as e:
        flash(f"Error fetching student results: {str(e)}", "danger")
        print(f"!!! ERROR fetching student results: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('search_page'))

    return render_template('results.html', student_name=student_name, student_results=student_results, sgpa_results=sgpa_results, cgpa=cgpa, htnumber=htnumber)

# Global variable to store section results for download.
# CAUTION: This can be a major memory hog for many students/sections.
# For production, consider generating the Excel on-the-fly without storing all data globally,
# or using a background task/caching mechanism.
section_results = {} # Initialize empty, will be populated by all_students route

@app.route('/all_students')
@login_required # Ensure only logged-in users can view all students
def all_students():
    global section_results # Declare intent to modify global variable

    semester_tables = [
        "y1_s1_results", "y1_s2_results", "y2_s1_results", "y2_s2_results",
        "y3_s1_results", "y3_s2_results", "y4_s1_results", "y4_s2_results"
    ]

    grade_values = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "COMPLE": 0, "NIL": 0}
    section_results = {} # Clear previous data to prevent stale/growing data

    try:
        student_conn = connect_student_db()
        result_conn = connect_results_db() # Use connect_results_db as per config.py

        with student_conn:
            with result_conn:
                student_cursor = student_conn.cursor()
                result_cursor = result_conn.cursor()

                # Get all section tables from student.db (assuming 'section_' prefix)
                student_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'section_%'")
                section_tables_in_db = [table['name'] for table in student_cursor.fetchall()]

                # Also include the general 'students' table if it exists in results.db
                result_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = 'students'")
                if result_cursor.fetchone():
                    section_tables_in_db.append('students')

                # Filter out 'uploaded_pdfs' or other non-section tables
                section_tables_in_db = [t for t in section_tables_in_db if t not in ['sqlite_sequence', 'uploaded_pdfs']]
                section_tables_in_db = list(set(section_tables_in_db)) # Remove duplicates if any

                for section in section_tables_in_db:
                    # Determine which database to query for student names
                    if section == 'students': # General students table is in results.db
                        current_student_cursor = result_cursor
                    else: # Section tables are in student.db
                        current_student_cursor = student_cursor

                    current_student_cursor.execute(f"SELECT roll_number, name FROM `{section}`")
                    students = current_student_cursor.fetchall()

                    section_cgpa_data = []

                    for student in students:
                        roll_number = str(student["roll_number"]).strip()
                        name = str(student["name"]).strip()

                        if "HP" not in roll_number: # Your specific filter, modify if needed
                            continue

                        total_cgpa_points_student = 0
                        total_cgpa_credits_student = 0

                        for table in semester_tables:
                            try:
                                result_cursor.execute(
                                    f"SELECT subname, grade, credits FROM `{table}` WHERE htno = ?", (roll_number,)
                                )
                                results = result_cursor.fetchall()

                                if results:
                                    total_credits_semester = 0
                                    total_grade_points_semester = 0

                                    for row in results:
                                        subname = row["subname"]
                                        grade = str(row["grade"]).strip().upper()
                                        credits = row["credits"] if row["credits"] is not None else 0.0

                                        # Attempt to fetch actual credits if current credits are zero or grade is non-passing
                                        if grade in ("F", "MP", "ABSENT", "COMPLE", "NIL") or credits == 0.0:
                                            try:
                                                result_cursor.execute(
                                                    f"SELECT credits FROM `{table}` WHERE subname = ? AND credits > 0 LIMIT 1",
                                                    (subname,)
                                                )
                                                fetched_credit_data = result_cursor.fetchone()
                                                if fetched_credit_data and fetched_credit_data['credits'] is not None:
                                                    credits = fetched_credit_data['credits']
                                                else:
                                                    credits = 0
                                            except sqlite3.Error as fetch_error:
                                                print(f"Error fetching credits for {subname}: {fetch_error}")
                                                credits = 0

                                        grade_point = grade_values.get(grade, 0)
                                        total_credits_semester += credits
                                        total_grade_points_semester += grade_point * credits

                                    if total_credits_semester > 0:
                                        total_cgpa_points_student += total_grade_points_semester
                                        total_cgpa_credits_student += total_credits_semester

                            except sqlite3.OperationalError:
                                # This table might not exist yet for certain semesters/years
                                print(f"Skipping missing results table {table} for roll number {roll_number}")
                            except Exception as e:
                                print(f"Error in {table} processing for {roll_number}: {e}")

                        cgpa = round(total_cgpa_points_student / total_cgpa_credits_student, 2) if total_cgpa_credits_student > 0 else "No CGPA"

                        section_cgpa_data.append({
                            "roll_number": roll_number,
                            "name": name,
                            "cgpa": cgpa
                        })
                        del student # Explicitly delete student data from memory after processing
                        gc.collect()

                    section_results[section] = section_cgpa_data

    except Exception as e:
        flash(f"Error fetching student CGPAs: {str(e)}", "danger")
        print(f"!!! ERROR fetching student CGPAs: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('home'))

    return render_template('all_students.html', section_results=section_results)


# --- Excel Download Routes ---
import openpyxl # Import here to ensure it's available for this section

# Download option for individual section results
@app.route('/download_section_excel/<section>')
@login_required # Ensure only logged-in users can download
def download_section_excel(section):
    """Generate and download an Excel file for a specific section."""
    # Re-fetch data if section_results might be stale or too large to keep in memory globally
    # For a robust solution, you might re-query the DB here instead of relying on global 'section_results'
    # especially if 'all_students' is not always visited right before download.
    if section not in section_results or not section_results[section]:
        flash("Section data not found or not loaded. Please visit /all_students first or try again.", "danger")
        return redirect(url_for('all_students'))

    # Create an in-memory binary stream for the Excel file
    output = io.BytesIO()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = f"{section}_CGPA"

    # Add headers
    ws.append(["Roll Number", "Name", "CGPA"])

    # Add data
    for student_data in section_results[section]:
        ws.append([student_data.get("roll_number"), student_data.get("name"), student_data.get("cgpa")])

    wb.save(output)
    output.seek(0) # Go to the beginning of the stream

    # Set up the response for file download
    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment;filename={section}_CGPA_Report.xlsx"}
    )

# Download all students CGPA data into a single Excel file
@app.route('/download_all_students_excel')
@login_required
def download_all_students_excel():
    global section_results # Use the globally stored data

    if not section_results:
        flash("No student CGPA data loaded. Please visit /all_students first.", "danger")
        return redirect(url_for('all_students'))

    output = io.BytesIO()
    wb = openpyxl.Workbook()

    for section_name, students_data in section_results.items():
        ws = wb.create_sheet(title=section_name)
        ws.append(["Roll Number", "Name", "CGPA"]) # Headers

        for student_data in students_data:
            ws.append([student_data.get("roll_number"), student_data.get("name"), student_data.get("cgpa")])

    # Remove the default 'Sheet' created initially if multiple sheets were added
    if 'Sheet' in wb.sheetnames:
        del wb['Sheet']

    wb.save(output)
    output.seek(0)

    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment;filename=All_Students_CGPA_Report.xlsx"}
    )


# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# --- App Initialization ---
if __name__ == '__main__':
    # Initialize all databases on app startup
    initialize_all_dbs()
    # It's good practice to call connect_auth_db, connect_results_db etc. from config.py
    # This also handles creating the persistent data directory if it doesn't exist.

    app.run(debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true', host='0.0.0.0', port=os.environ.get('PORT', 5000))
