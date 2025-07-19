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
import gc
import sys # Import sys for sys.stdout
import secrets # Import secrets for token_hex
import logging # Import logging module

from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

# Import Redis and RQ
from redis import Redis
from rq import Queue, get_current_job
from rq.exceptions import NoSuchJobError

# Import from config.py - Consolidated and using correct names
from config import (
    connect_auth_db, connect_results_db, connect_student_db,
    initialize_all_dbs, AUTH_DB_PATH, RESULTS_DB_PATH, STUDENT_DB_PATH
)

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

logger.info("Starting Flask application initialization...")

app = Flask(__name__)
logger.info("Flask app instance created.")

# Generate a strong, random SECRET_KEY for sessions
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
logger.info("SECRET_KEY configured.")

# Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'darkplayer1335@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'uqic wxbn pnfe khqt')
mail = Mail(app)
logger.info("Flask-Mail configured.")


# RQ (Redis Queue) setup - Consolidated to one block
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
logger.info(f"Attempting to connect to Redis at: {REDIS_URL}")
try:
    redis_conn = Redis.from_url(REDIS_URL)
    # Ping Redis to ensure connection is live. If not, it will raise an error.
    redis_conn.ping()
    q = Queue(connection=redis_conn) # Use 'q' consistently
    logger.info("Redis and RQ Queue initialized and connected successfully.")
except Exception as e:
    logger.critical(f"FATAL ERROR: Could not connect to Redis or initialize RQ: {e}", exc_info=True)
    # This is a critical dependency. If Redis isn't working, the app can't function.
    # Re-raise to prevent the Flask app from starting if Redis is down.
    raise

# Initialize databases
try:
    initialize_all_dbs()
    logger.info("All databases initialized successfully.")
except Exception as e:
    logger.critical(f"FATAL ERROR: During database initialization: {e}", exc_info=True)
    # This is a critical dependency. If DBs can't initialize, the app can't function.
    raise

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)
logger.info("Flask-Login initialized.")

# Define upload folders
UPLOAD_FOLDER = "uploads" # This will be used to temporarily store files before workers pick them up
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
logger.info(f"Ensured UPLOAD_FOLDER exists: {UPLOAD_FOLDER}")

# Set a maximum content length for uploads (e.g., 100 MB)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 # 100 MB
logger.info("MAX_CONTENT_LENGTH set.")

# --- Import the background task function ---
from tasks import process_pdf_task
logger.info("Imported process_pdf_task from tasks.py.")


# --- Helper Functions (keep them here as they are used by Flask routes) ---
def generate_token():
    """Generates a random alphanumeric token."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def generate_pdf_hash(file_path):
    """Generates SHA256 hash for the uploaded PDF."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
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
                                 (username, email, hashed_password, 0))
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
def search_page():
    return render_template('search.html')

@app.route('/upload_details')
def details_page():
    return render_template('upload_student_details.html')

@app.route('/upload_results')
def results_page():
    return render_template('upload_student_results.html')

# Uploading students results - MODIFIED FOR RQ
@app.route('/upload', methods=['POST'])
@login_required
def upload_pdf():
    print("--- Inside /upload POST request ---")
    if 'pdf_file' not in request.files:
        flash('No file selected', 'yellow')
        print("No file selected in request.")
        return redirect(url_for('results_page'))

    file = request.files['pdf_file']
    year = request.form.get('year')
    semester = request.form.get('semester')

    if file.filename == '' or not year or not semester:
        flash('Missing file, year, or semester input', 'yellow')
        print("Missing file, year, or semester input.")
        return redirect(url_for('results_page'))

    # Sanitize table name
    table_name = f"y{year}_s{semester}_results"
    table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name)

    # Use a unique filename to prevent clashes if multiple users upload same filename
    unique_filename = f"{os.path.splitext(file.filename)[0]}_{random.randint(1000, 9999)}{os.path.splitext(file.filename)[1]}"
    temp_pdf_path = os.path.join(UPLOAD_FOLDER, unique_filename)

    try:
        file.save(temp_pdf_path)
        print(f"File saved to temp path: {temp_pdf_path}")
    except Exception as e:
        flash(f"Error saving uploaded file: {str(e)}", 'danger')
        print(f"!!! ERROR saving uploaded file: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('results_page'))

    try:
        # Enqueue the task to the Redis Queue
        job = q.enqueue(
            process_pdf_task,
            temp_pdf_path,
            year,
            semester,
            table_name,
            RESULTS_DB_PATH, # Corrected: Use RESULTS_DB_PATH
            job_timeout='10m',
            result_ttl=5000,
            meta={'user_id': current_user.id}
        )

        flash(f'PDF upload received. Processing started in the background (Job ID: {job.id}).', 'info')
        print(f"PDF processing job enqueued: {job.id}")
        session['last_upload_job_id'] = job.id

        return redirect(url_for('results_page'))

    except Exception as e:
        flash(f'Error enqueuing PDF processing task: {str(e)}', 'danger')
        print(f"!!! ERROR enqueuing task: {e}")
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)
        import traceback
        traceback.print_exc()
        return redirect(url_for('results_page'))

# --- New endpoint to check job status (optional but recommended) ---
@app.route('/upload_status/<job_id>')
@login_required
def upload_status(job_id):
    try:
        job = q.fetch_job(job_id)
        if job is None:
            return jsonify({'status': 'not_found', 'message': 'Job not found'}), 404
        
        status = job.get_status()
        result = job.result

        if status == 'failed':
            return jsonify({'status': status, 'message': 'Processing failed', 'error': str(job.exc_info)}), 200
        elif status == 'finished':
            return jsonify({'status': status, 'message': 'Processing complete', 'result': result}), 200
        else:
            return jsonify({'status': status, 'message': 'Processing in progress...'}), 200
            
    except NoSuchJobError:
        return jsonify({'status': 'not_found', 'message': 'Job ID not recognized by Redis Queue.'}), 404
    except Exception as e:
        print(f"Error checking job status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500

# --- Search and Display Routes ---
@app.route('/get_results', methods=['POST'])
def get_results():
    htnumber = request.form.get('htno')
    if len(htnumber) != 10:
        flash('Invalid roll number', 'warning')
        return redirect(url_for('search_page'))

    semester_tables = ["y1_s1_results", "y1_s2_results", "y2_s1_results", "y2_s2_results",
                        "y3_s1_results", "y3_s2_results", "y4_s1_results", "y4_s2_results"]

    student_results = {}
    sgpa_results = {}
    total_cgpa_points = 0
    total_cgpa_credits = 0

    grade_values = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "COMPLE": 0}

    # Connect to the correct databases
    conn_main = connect_results_db() # Corrected: Use connect_results_db
    conn_student = connect_student_db()

    student_name = "Unknown"

    try:
        with conn_main:
            with conn_student:
                cursor_main = conn_main.cursor()
                cursor_student = conn_student.cursor()

                # Fetch student name from the 'students' table in 'results.db' (assuming this is where it resides for search)
                cursor_main.execute("SELECT name FROM students WHERE roll_number = ? LIMIT 1", (htnumber,))
                student_name_data = cursor_main.fetchone()
                student_name = student_name_data['name'] if student_name_data else "Unknown"

                for table in semester_tables:
                    try:
                        cursor_main.execute(f"SELECT subname, grade, credits FROM `{table}` WHERE htno = ?", (htnumber,))
                        results = cursor_main.fetchall()
                        student_results[table] = results if results else "No Data"

                        if results:
                            total_credits_semester = 0
                            total_grade_points_semester = 0

                            for row in results:
                                subname = row['subname']
                                grade = row['grade']
                                credits = row['credits']

                                if grade.upper() in ("F", "MP", "ABSENT") or credits == 0.0:
                                    try:
                                        cursor_main.execute( # Query the results.db
                                            f"SELECT credits FROM `{table}` WHERE subname = ? AND grade NOT IN ('F', 'MP', 'ABSENT', 'COMPLE') LIMIT 1",
                                            (subname,)
                                        )
                                        fetched_credit_data = cursor_main.fetchone()
                                        if fetched_credit_data and fetched_credit_data['credits'] is not None:
                                            credits = fetched_credit_data['credits']
                                        else:
                                            credits = 0
                                    except sqlite3.Error as fetch_error:
                                        print(f"Error fetching credits for {subname}: {fetch_error}")
                                        credits = 0

                                grade_point = grade_values.get(grade.upper(), 0)
                                total_credits_semester += credits
                                total_grade_points_semester += grade_point * credits

                            if total_credits_semester > 0:
                                sgpa_results[table] = round(total_grade_points_semester / total_credits_semester, 2)
                            else:
                                sgpa_results[table] = "No SGPA"

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
section_results = {}

@app.route('/all_students')
@login_required
def all_students():
    global section_results

    semester_tables = [
        "y1_s1_results", "y1_s2_results", "y2_s1_results", "y2_s2_results",
        "y3_s1_results", "y3_s2_results", "y4_s1_results", "y4_s2_results"
    ]

    grade_values = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "COMPLE": 0}
    section_results = {}

    try:
        student_conn = connect_student_db()
        result_conn = connect_results_db() # Corrected: Use connect_results_db

        with student_conn:
            with result_conn:
                student_cursor = student_conn.cursor()
                result_cursor = result_conn.cursor()

                # Get section tables from the student_db (e.g., 'cse_a', 'ece_b')
                student_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                section_tables_in_db = [table['name'] for table in student_cursor.fetchall() if table['name'] != 'students']

                for section in section_tables_in_db:
                    student_cursor.execute(f"SELECT roll_number, name FROM `{section}`")
                    students = student_cursor.fetchall()

                    section_cgpa_data = []

                    for student in students:
                        roll_number = student["roll_number"]
                        name = student["name"]

                        if "HP" not in roll_number: # Filter for 'HP' in roll_number
                            continue

                        total_cgpa_points_student = 0
                        total_cgpa_credits_student = 0

                        for table in semester_tables:
                            try:
                                result_cursor.execute( # Query the result_db for grades
                                    f"SELECT subname, grade, credits FROM `{table}` WHERE htno = ?", (roll_number,)
                                )
                                results = result_cursor.fetchall()

                                if results:
                                    total_credits_semester = 0
                                    total_grade_points_semester = 0

                                    for row in results:
                                        subname = row["subname"]
                                        grade = row["grade"]
                                        credits = row["credits"]

                                        if grade.upper() in ("F", "MP", "ABSENT") or credits == 0.0:
                                            try:
                                                result_cursor.execute(
                                                    f"SELECT credits FROM `{table}` WHERE subname = ? AND grade NOT IN ('F', 'MP', 'ABSENT', 'COMPLE') LIMIT 1",
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

                                        grade_point = grade_values.get(grade.upper(), 0)
                                        total_credits_semester += credits
                                        total_grade_points_semester += grade_point * credits

                                    if total_credits_semester > 0:
                                        total_cgpa_points_student += total_grade_points_semester
                                        total_cgpa_credits_student += total_credits_semester

                            except sqlite3.OperationalError:
                                print(f"Skipping missing table {table} for roll number {roll_number}")
                            except Exception as e:
                                print(f"Error in {table} processing for {roll_number}: {e}")

                        cgpa = round(total_cgpa_points_student / total_cgpa_credits_student, 2) if total_cgpa_credits_student > 0 else "No CGPA"

                        section_cgpa_data.append({
                            "roll_number": roll_number,
                            "name": name,
                            "cgpa": cgpa
                        })
                        del student
                        gc.collect()

                    section_results[section] = section_cgpa_data

    except Exception as e:
        flash(f"Error fetching student CGPAs: {str(e)}", "danger")
        print(f"!!! ERROR fetching student CGPAs: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('home'))

    return render_template('all_students.html', section_results=section_results)

# Download option for individual section results
@app.route('/download_section_excel/<section>')
@login_required
def download_section_excel(section):
    import openpyxl # Import openpyxl here

    if section not in section_results:
        flash("Section data not found or not loaded. Please visit /all_students first.", "danger")
        return redirect(url_for('all_students'))
    
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = f"{section}_CGPA"

    ws.append(["Roll Number", "Name", "CGPA"])
    
    for student_data in section_results[section]:
        ws.append([student_data["roll_number"], student_data["name"], student_data["cgpa"]])

    excel_file = io.BytesIO()
    wb.save(excel_file)
    excel_file.seek(0)

    return Response(
        excel_file.read(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment;filename={section}_CGPA.xlsx"}
    )

if __name__ == '__main__':
    initialize_all_dbs()
    app.run(debug=True)
