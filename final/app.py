import os
import io
import bcrypt
import pandas as pd
import tabula # Keeping this import for clarity, though it's mainly used in worker.py for actual PDF processing
import hashlib
#import re
import random
import string
import sqlite3
import gc # Import garbage collection module
import secrets # For secure filenames

from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, Response, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash # Keep if potentially used elsewhere, though bcrypt is main
from werkzeug.utils import secure_filename

from flask_mail import Mail, Message # Assuming you've configured Flask-Mail

# --- IMPORTANT: Celery Imports and Setup ---
# Import the configured Celery app and ALL necessary tasks from worker.py
from worker import celery_app, process_excel_task, generate_pdf_task, process_marks_pdf_task # <-- ADDED process_marks_pdf_task

# Assuming config.py is in the same directory and contains these connection functions
# Ensure config.py defines: connect_auth_db, connect_results_db, connect_student_db, initialize_all_dbs
# and the DATABASE_DIR for persistent storage.
from config import connect_auth_db, connect_results_db, connect_student_db, initialize_all_dbs, DATABASE_DIR

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16)) # Use an environment variable in production!
app.config['UPLOAD_FOLDER'] = os.path.join(DATABASE_DIR, 'uploads')

# Ensure UPLOAD_FOLDER exists at app startup
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Route name for login page

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin # Custom attribute to check admin status

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    conn = connect_auth_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data:
        return User(user_data['id'], user_data['username'], bool(user_data['is_admin']))
    return None

# --- Helper function for allowed file types ---
ALLOWED_EXTENSIONS = {'xls', 'xlsx', 'pdf'}

def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

# --- Routes ---

@app.before_request
def before_request_func():
    # Example of initializing DBs at app start (safe with IF NOT EXISTS)
    # This ensures tables are present for routes that need them immediately.
    # It's also called in worker, which is fine.
    initialize_all_dbs()

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return render_template('admin_dashboard.html', username=current_user.username)
        else:
            return render_template('student_dashboard.html', username=current_user.username)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = connect_auth_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash']):
            user = User(user_data['id'], user_data['username'], bool(user_data['is_admin']))
            login_user(user)
            session['is_admin'] = user.is_admin # Store admin status in session
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('is_admin', None) # Remove admin status from session
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Only allow admin to register new users (or remove this check if anyone can register)
    # This route might be better placed in an admin dashboard, or restricted by an admin token
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = request.form.get('is_admin') == 'on' # Checkbox value

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = connect_auth_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                           (username, hashed_password, is_admin))
            conn.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')
        finally:
            conn.close()
    return render_template('register.html')


# --- Excel File Upload Route ---
@app.route('/upload_excel', methods=['GET', 'POST']) # Renamed for clarity vs. PDF upload
@login_required
def upload_excel():
    if not current_user.is_admin:
        flash('Unauthorized: Only administrators can upload Excel files.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if not allowed_file(file.filename, ['xls', 'xlsx']):
            flash('Invalid file type. Please upload an Excel file (.xls or .xlsx).', 'danger')
            return redirect(request.url)

        year = request.form.get('year')
        exam_type = request.form.get('exam_type')
            # Sanitize exam_type for filename/table name
        exam_type = re.sub(r'[^a-zA-Z0-9_]', '', exam_type).lower() if exam_type else 'unknown_exam'

        course = request.form.get('course')
            # Sanitize course for filename/table name
        course = re.sub(r'[^a-zA-Z0-9_]', '', course).lower() if course else 'unknown_course'

        semester = request.form.get('semester')
            # Sanitize semester for filename/table name
        semester = re.sub(r'[^a-zA-Z0-9_]', '', semester).lower() if semester else 'unknown_semester'


        if not all([year, exam_type, course, semester]):
            flash('Please fill all required fields (Year, Exam Type, Course, Semester).', 'danger')
            return redirect(request.url)

        # Generate a secure filename
        filename = secrets.token_hex(8) + "_" + secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            # Hash file content to check for duplicates BEFORE saving
            file_content = file.read()
            file_hash = hashlib.sha256(file_content).hexdigest()
            file.seek(0) # Reset file pointer after reading for hash

            conn_results = connect_results_db()
            with conn_results:
                cursor_results = conn_results.cursor()
                cursor_results.execute("SELECT id FROM uploaded_pdfs WHERE pdf_hash = ?", (file_hash,))
                if cursor_results.fetchone():
                    flash(f"File {file.filename} (hash: {file_hash}) already processed. Skipping.", 'warning')
                    return redirect(request.url)

            file.save(file_path)
            flash(f"File {filename} uploaded successfully. Processing in background...", 'info')

            # Dispatch task to Celery
            task = process_excel_task.delay(file_path, year, exam_type, course, semester)
            return render_template('upload_excel.html', message=f"Processing started, Task ID: {task.id}", task_id=task.id)

        except Exception as e:
            flash(f'Error uploading Excel file: {str(e)}', 'danger')
            app.logger.error(f"Error during Excel upload: {e}", exc_info=True)
            if os.path.exists(file_path):
                os.remove(file_path) # Clean up if something went wrong before enqueuing
            return render_template('error.html', error_message=f"Error uploading Excel: {e}"), 500

    return render_template('upload_excel.html') # A GET request to /upload_excel will show this template

# --- PDF Marks Upload Route (as per your log) ---
@app.route('/upload_pdf', methods=['GET', 'POST']) # Retaining /upload_pdf as per your latest log context
@login_required
def upload_pdf():
    print("--- Inside /upload_pdf POST request ---")
    if not current_user.is_admin:
        flash('Unauthorized: Only administrators can upload PDF files.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        if 'pdf_file' not in request.files:
            flash('No file selected', 'warning')
            print("No file selected in request.")
            return redirect(url_for('results_page')) # Assuming results_page is main page for results

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

        # Generate a unique filename to prevent clashes, using hash + original name
        file_content = file.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        file.seek(0) # Reset file pointer after reading for hash

        unique_filename = f"{file_hash}_{secure_filename(file.filename)}"
        temp_pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        try:
            # Check if this PDF (by hash) has been uploaded before in results.db (uploaded_pdfs table)
            conn_results = connect_results_db()
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
                    return redirect(url_for('results_page')) # Or redirect back to the upload form

            file.save(temp_pdf_path)
            print(f"File saved to temp path: {temp_pdf_path}")

            # --- Enqueue the PDF processing task to the Celery queue ---
            # Now 'process_marks_pdf_task' is imported from worker.py
            task = process_marks_pdf_task.delay(temp_pdf_path, year, semester)

            flash('PDF uploaded. Processing has started in the background...', 'info')
            print(f"Finished /upload_pdf POST request, task enqueued with ID: {task.id}.")
            return render_template('upload_pdf.html', message=f"Processing started, Task ID: {task.id}", task_id=task.id) # Show feedback on PDF upload page

        except Exception as e:
            flash(f'Error uploading PDF: {str(e)}', 'danger')
            print(f"!!! ERROR during PDF upload and enqueue: {e}")
            import traceback
            traceback.print_exc()
            if os.path.exists(temp_pdf_path):
                os.remove(temp_pdf_path) # Clean up if something went wrong before enqueuing
            return render_template('error.html', error_message=f"Error uploading PDF: {e}"), 500
    
    # For GET request to /upload_pdf
    return render_template('upload_pdf.html')


# --- Route to check Celery task status (useful for AJAX polling) ---
@app.route('/task_status/<task_id>')
def task_status(task_id):
    task = celery_app.AsyncResult(task_id)
    response = {
        'state': task.state,
        'status': 'Pending...' if task.state == 'PENDING' else task.info.get('status', 'Unknown'),
        'message': task.info.get('message', 'Processing...')
    }
    if task.state == 'FAILURE':
        response['error'] = str(task.info) # Get the full error traceback
    return jsonify(response)


# --- Student Result Lookup ---
@app.route('/student_result', methods=['GET', 'POST'])
@login_required # Assuming students need to be logged in to view their results
def student_result():
    # Only allow non-admins (students) or admins to view this if needed
    if request.method == 'POST':
        roll_number = request.form.get('roll_number')
        year = request.form.get('year')
        exam_type = request.form.get('exam_type')
        course = request.form.get('course')
        semester = request.form.get('semester')

        if not all([roll_number, year, exam_type, course, semester]):
            flash('Please fill all search criteria.', 'danger')
            return render_template('student_result.html', result=None)

        student_conn = None
        result_data = None
        try:
            student_conn = connect_student_db()
            student_conn.row_factory = sqlite3.Row # Ensure rows can be accessed by column name
            cursor = student_conn.cursor()
            table_name = f"results_{year}_{exam_type}_{course}_{semester}".lower()
            table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name) # Sanitize

            # Check if table exists before querying
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            if not cursor.fetchone():
                flash(f"No results found for the specified criteria (table '{table_name}' does not exist).", 'warning')
                return render_template('student_result.html', result=None)

            cursor.execute(f"SELECT * FROM {table_name} WHERE roll_number = ?", (roll_number,))
            result_data = cursor.fetchone()

            if result_data:
                result_data = dict(result_data) # Convert sqlite3.Row to dictionary
                flash('Result found!', 'success')
            else:
                flash('No result found for the given Roll Number and criteria.', 'warning')
        except Exception as e:
            flash(f"An error occurred: {e}", 'danger')
            app.logger.error(f"Error fetching student result: {e}", exc_info=True)
        finally:
            if student_conn:
                student_conn.close()
        return render_template('student_result.html', result=result_data)
    return render_template('student_result.html', result=None)


# --- Placeholder for generate_pdf_task trigger ---
@app.route('/generate_student_pdf', methods=['POST'])
@login_required # Restrict access as needed
def generate_student_pdf_route(): # Renamed to avoid confusion with the task itself
    # You'll need to pass the parameters from a form or URL query
    roll_number = request.form.get('roll_number') # Or request.args.get() if from URL
    year = request.form.get('year')
    exam_type = request.form.get('exam_type')
    course = request.form.get('course')
    semester = request.form.get('semester')

    if not all([roll_number, year, exam_type, course, semester]):
        flash('Please provide all details to generate the PDF.', 'danger')
        return redirect(url_for('student_result'))

    # Dispatch the PDF generation task to Celery
    task = generate_pdf_task.delay(roll_number, year, exam_type, course, semester)
    flash(f"PDF generation started for Roll No: {roll_number}. Task ID: {task.id}", 'info')
    return redirect(url_for('student_result', task_id=task.id)) # Redirect back to results page, maybe add task_id to URL for status check


@app.route('/results_page') # A generic page to view results or upload options
@login_required
def results_page():
    # This could be a dashboard showing different upload forms or result viewing options
    return render_template('results_page.html')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404 # Ensure you have a 404.html template

@app.errorhandler(403)
def forbidden(e):
    flash("You do not have permission to access this page.", 'danger')
    return redirect(url_for('home'))


if __name__ == '__main__':
    # Initialize all databases on Flask app startup
    # This is safe because initialize_all_dbs uses "CREATE TABLE IF NOT EXISTS"
    print("Flask app starting up. Initializing databases...")
    initialize_all_dbs()
    print("Databases initialized by Flask app.")
    app.run(debug=True, host='0.0.0.0', port=os.getenv('PORT', 5000))
