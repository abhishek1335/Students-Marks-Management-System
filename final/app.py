import os
import io
import bcrypt
import pandas as pd
import tabula # Keep this, as tabula-py is used in worker.py for PDF processing
import hashlib
import re
import random
import string
import sqlite3
import gc # Import garbage collection module

from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, Response, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash # Keep if potentially used elsewhere, though bcrypt is main
from werkzeug.utils import secure_filename # ADDED: This was missing but used

from flask_mail import Mail, Message

# --- IMPORTANT: Celery Imports and Setup ---
# Import the configured Celery app and tasks from worker.py
from worker import celery_app, process_excel_task, generate_pdf_task

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

# --- REMOVED: process_excel_to_section_tables and process_excel_to_single_students_table
# These functions should ONLY exist in worker.py as Celery tasks.

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

        # Enqueue the excel processing task to the Celery queue
        process_section_excel_task.delay(excel_path)
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

        # Enqueue the excel processing task to the Celery queue
        process_single_student_excel_task.delay(excel_path)
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
    # Note: The worker task `process_marks_pdf_task` defines the dynamic table name.
    # This `table_name` variable here is just for local app context if needed.
    table_name = f"y{year}_s{semester}_results"
    table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name)

    # Generate a unique filename to prevent clashes, using hash + original name
    # Read the file content for hashing, then seek back to 0 for saving.
    file_content = file.read()
    file_hash = hashlib.sha256(file_content).hexdigest()
    file.seek(0) # Reset file pointer after reading for hash

    unique_filename = f"{file_hash}_{secure_filename(file.filename)}" # Use secure_filename for original name part
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
            cursor_results.execute("SELECT pdf_hash FROM uploaded_pdfs WHERE pdf_hash = ?", (file_hash,))
            if cursor_results.fetchone():
                flash("This PDF has already been uploaded. No changes made.", 'warning')
                print(f"PDF {file.filename} already uploaded (hash: {file_hash}).")
                return redirect(url_for('results_page'))

        file.save(temp_pdf_path)
        print(f"File saved to temp path: {temp_pdf_path}")

        # --- Enqueue the PDF processing task to the Celery queue ---
        # Call the task with .delay()
        # The 'process_marks_pdf_task' function MUST be in worker.py and decorated with @celery_app.task
        process_marks_pdf_task.delay(temp_pdf_path, year, semester)

        # The worker will insert the hash into uploaded_pdfs table *after* successful processing.
        # This prevents marking it as processed if the worker fails.

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
                # Set row_factory for both connections to enable dict-like access
                conn_results.row_factory = sqlite3.Row
                conn_student.row_factory = sqlite3.Row

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
                # Set row_factory for both connections to enable dict-like access
                student_conn.row_factory = sqlite3.Row
                result_conn.row_factory = sqlite3.Row

                student_cursor = student_conn.cursor()
                result_cursor = result_conn.cursor()

                # Get all section tables from student.db (assuming 'section_' prefix)
                student_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'section_%'")
                section_tables_in_db = [table['name'] for table in student_cursor.fetchall()]

                # Also include the general 'students' table if it exists in results.db
                result_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = 'students'")
                if result_cursor.fetchone():
                    section_tables_in_db.append('students')

                # Filter out 'sqlite_sequence' or other non-section tables
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
                                                    credits = 0 # Default if no valid credits found
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
                                print(f"Table {table} not found for {roll_number}, skipping.")
                                continue # Skip to next table if it doesn't exist
                            except Exception as e:
                                print(f"Error processing {table} for {roll_number}: {e}")
                                continue

                        student_cgpa = round(total_cgpa_points_student / total_cgpa_credits_student, 2) if total_cgpa_credits_student > 0 else "N/A"
                        section_cgpa_data.append({"roll_number": roll_number, "name": name, "cgpa": student_cgpa})

                    section_results[section] = section_cgpa_data
        
        # Manually trigger garbage collection after processing a large amount of data
        gc.collect()

    except Exception as e:
        flash(f"Error fetching all students: {str(e)}", "danger")
        print(f"!!! ERROR fetching all students: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('admin_dashboard'))

    return render_template('all_students.html', section_results=section_results)

@app.route('/download_section_cgpa_excel')
@login_required
def download_section_cgpa_excel():
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    if not section_results:
        flash("No data available to download. Please view 'All Students' first.", "warning")
        return redirect(url_for('all_students'))

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        for section_name, students_data in section_results.items():
            if students_data: # Only create sheet if there's data for the section
                df = pd.DataFrame(students_data)
                df.to_excel(writer, sheet_name=section_name[:30], index=False) # Sheet names max 31 chars

    output.seek(0)
    return send_file(output, as_attachment=True, download_name='all_students_cgpa.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/get_download_pdf', methods=['POST'])
@login_required
def get_download_pdf():
    roll_number = request.form.get('roll_number')
    year = request.form.get('year')
    exam_type = request.form.get('exam_type')
    course = request.form.get('course')
    semester = request.form.get('semester')

    if not all([roll_number, year, exam_type, course, semester]):
        flash("All fields (Roll Number, Year, Exam Type, Course, Semester) are required to generate PDF.", "danger")
        return redirect(url_for('search_page'))

    # Enqueue the PDF generation task to the Celery queue
    # The 'generate_pdf_task' function MUST be in worker.py and decorated with @celery_app.task
    task = generate_pdf_task.delay(roll_number, year, exam_type, course, semester)
    
    # Store task ID in session to allow polling for status
    session['pdf_generation_task_id'] = task.id
    
    flash("PDF generation has been started in the background. Please wait and check the status page.", "info")
    return redirect(url_for('pdf_status')) # Redirect to a status page

@app.route('/pdf_status')
@login_required
def pdf_status():
    task_id = session.get('pdf_generation_task_id')
    if not task_id:
        flash("No PDF generation task found.", "warning")
        return redirect(url_for('search_page'))

    # Get the Celery task by ID
    task = celery_app.AsyncResult(task_id)

    if task.state == 'PENDING':
        response = {'status': 'Pending', 'message': 'PDF generation is pending.'}
    elif task.state == 'STARTED':
        response = {'status': 'Processing', 'message': 'PDF generation is in progress.'}
    elif task.state == 'SUCCESS':
        result = task.result
        if result and result.get('status') == 'success':
            pdf_path = result.get('path')
            response = {'status': 'Success', 'message': 'PDF generated successfully!', 'download_url': url_for('download_generated_pdf', filename=os.path.basename(pdf_path))}
            session.pop('pdf_generation_task_id', None) # Clear task ID from session
        else:
            response = {'status': 'Failure', 'message': result.get('message', 'PDF generation failed.')}
            session.pop('pdf_generation_task_id', None) # Clear task ID from session
    elif task.state == 'FAILURE':
        response = {'status': 'Failure', 'message': f'PDF generation failed: {task.info}'}
        session.pop('pdf_generation_task_id', None) # Clear task ID from session
    else:
        response = {'status': task.state, 'message': 'Unknown task status.'}
    
    return render_template('pdf_status.html', response=response)

@app.route('/download_generated_pdf/<filename>')
@login_required
def download_generated_pdf(filename):
    # Ensure the file is within the allowed directory
    # IMPORTANT: Adjust 'generated_pdfs' to match the actual output folder in worker.py
    pdf_dir = os.path.join(DATABASE_DIR, 'generated_pdfs')
    file_path = os.path.join(pdf_dir, filename)

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True, download_name=filename, mimetype='application/pdf')
    else:
        flash("File not found.", "danger")
        return redirect(url_for('pdf_status'))


# --- Initialize all databases when the app starts up ---
# This is safe to call multiple times as CREATE TABLE IF NOT EXISTS handles existing tables.
# This ensures that tables are ready before the application tries to interact with them.
print("App starting up. Initializing databases...")
initialize_all_dbs()
print("Databases initialized.")

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true', host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
