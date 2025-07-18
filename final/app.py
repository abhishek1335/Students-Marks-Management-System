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

from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

# Assuming config.py is in the same directory and contains these connection functions
from config import connect_auth_db, connect_db, connect_result_db, connect_student_db, initialize_all_dbs

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_from_env') # Use env var for production
mail = Mail(app)

# Mail configuration - IMPORTANT: Use environment variables for sensitive info in production
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'darkplayer1335@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'uqic wxbn pnfe khqt') # Use app password, not main password

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Define upload folders
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Ensure directory exists at app startup

# Note: UPLOAD_FOLDER1 seems unused in the provided code, consider removing if not needed.
UPLOAD_FOLDER1 = "uploads1"
os.makedirs(UPLOAD_FOLDER1, exist_ok=True)

# Set a maximum content length for uploads (e.g., 100 MB)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 # 100 MB

# --- Helper Functions ---

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
                    # Log the full traceback for more detailed debugging
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

        if entered_token == session.get('reset_token'): # Use .get() for safety
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            conn = connect_auth_db()
            with conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_new_password, session['reset_email']))
                conn.commit()

            session.pop('reset_token', None) # Use .pop(key, default) for safety
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

# Uploading students results
@app.route('/upload', methods=['POST'])
@login_required # Ensure only logged-in users can upload
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

    temp_pdf_path = os.path.join(UPLOAD_FOLDER, file.filename)
    
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
        conn = connect_db()
        with conn:
            cursor = conn.cursor()

            # Ensure uploaded_pdfs table exists
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS uploaded_pdfs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pdf_hash TEXT UNIQUE
            );
            """)

            # Check if the PDF is already uploaded
            pdf_hash = generate_pdf_hash(temp_pdf_path)
            cursor.execute("SELECT pdf_hash FROM uploaded_pdfs WHERE pdf_hash = ?", (pdf_hash,))
            if cursor.fetchone():
                flash("This PDF has already been uploaded. No changes made.", 'warning')
                print(f"PDF {file.filename} already uploaded (hash: {pdf_hash}).")
                os.remove(temp_pdf_path)
                return redirect(url_for('results_page'))

            # Create results table dynamically if not exists
            cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS `{table_name}` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                htno TEXT,
                subcode TEXT,
                subname TEXT,
                internals INTEGER,
                grade TEXT,
                credits REAL,
                UNIQUE(htno, subcode)
            );
            """)

            print(f"Starting tabula.read_pdf for {temp_pdf_path}...")
            # Use 'stream=True' for potentially lower memory usage.
            # If large PDFs are still crashing, consider processing pages individually
            # if tabula-py supports it easily for your use case, or splitting the PDF.
            tables = tabula.read_pdf(temp_pdf_path, pages="all", multiple_tables=True, stream=True)
            print(f"Tabula extraction complete. Found {len(tables)} tables.")
            
            # Explicitly remove temporary PDF file as soon as it's read
            os.remove(temp_pdf_path)
            print(f"Removed temporary PDF file: {temp_pdf_path}")
            gc.collect() # Trigger garbage collection

            # Process tables in chunks to avoid large DataFrame concatenation
            all_data = []
            for i, table_df in enumerate(tables):
                print(f"Processing table {i+1} from PDF...")
                if table_df.empty:
                    print(f"Table {i+1} is empty, skipping.")
                    continue

                # Standardize column names
                table_df.columns = [col.strip().replace('.', '').capitalize() for col in table_df.columns]

                if "Sno" in table_df.columns:
                    table_df = table_df.drop(columns=["Sno"])

                expected_columns_template = ["Htno", "Subcode", "Subname", "Internals", "Grade", "Credits"]
                
                # Filter and reorder columns
                current_columns = [col for col in table_df.columns if col in expected_columns_template]
                df_filtered = table_df[current_columns].copy() # Use .copy() to avoid SettingWithCopyWarning

                # Ensure all expected columns are present, fill with None if not
                for col in expected_columns_template:
                    if col not in df_filtered.columns:
                        df_filtered[col] = None
                df_filtered = df_filtered[expected_columns_template] # Reorder for consistent insertion

                df_filtered = df_filtered.dropna(subset=["Htno", "Subcode"]) # Drop rows missing essential IDs
                df_filtered = df_filtered[df_filtered["Htno"].astype(str).str.lower() != "htno"] # Remove header rows

                # Clean data types
                def clean_int_data(value):
                    if pd.isna(value) or str(value).strip() in ('---', '', 'N/A', 'nan'):
                        return 0
                    try:
                        return int(float(str(value).strip()))
                    except ValueError:
                        return 0

                def clean_float_data(value):
                    if pd.isna(value) or str(value).strip() in ('---', '', 'N/A', 'nan'):
                        return 0.0
                    try:
                        return float(str(value).strip())
                    except ValueError:
                        return 0.0

                df_filtered["Internals"] = df_filtered["Internals"].apply(clean_int_data)
                df_filtered["Credits"] = df_filtered["Credits"].apply(clean_float_data)
                
                all_data.extend(df_filtered.to_records(index=False).tolist())
                
                # Explicitly delete DataFrame to free memory after processing each table
                del table_df
                del df_filtered
                gc.collect()

            # Insert or update records in batches
            # This is more efficient than row-by-row insertion in a loop
            # SQLite's UPSERT (INSERT OR REPLACE / INSERT ON CONFLICT) is ideal here
            # We'll use INSERT OR REPLACE for simplicity, assuming new data replaces old for same HTNO/SUBCODE
            # If you need more complex merge logic, you'd need separate SELECT/UPDATE/INSERT.

            # Define the grade ranking for update logic
            grade_rank = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "NO CHANGE": -1} # Assign ranks, lower is worse for 'NO CHANGE'

            insert_count = 0
            update_count = 0

            # Process all_data (list of tuples)
            for row_tuple in all_data:
                htno, subcode, subname, internals, grade, credits = row_tuple
                
                htno = str(htno).strip()
                subcode = str(subcode).strip()
                subname = str(subname).strip()
                grade = str(grade).strip()

                # Check for existing record to apply update logic
                cursor.execute(f"SELECT grade, credits FROM `{table_name}` WHERE htno = ? AND subcode = ?", (htno, subcode))
                existing_record = cursor.fetchone()

                if existing_record:
                    existing_grade, existing_credits = existing_record
                    # Prioritize the new grade if it's better OR if the old one was a placeholder
                    # "Better" means higher grade_rank value (A+ is 10, F is 0)
                    new_grade_rank = grade_rank.get(grade.upper(), -1)
                    old_grade_rank = grade_rank.get(existing_grade.upper(), -1)

                    should_update = False
                    if new_grade_rank > old_grade_rank: # New grade is strictly better
                        should_update = True
                    elif old_grade_rank <= 0 and new_grade_rank > 0: # Old was F/MP/ABSENT/NO CHANGE, new is passing
                        should_update = True
                    elif new_grade_rank == old_grade_rank and credits != existing_credits: # Same grade, but credits changed (e.g., from 0 to actual)
                        should_update = True

                    if should_update:
                        cursor.execute(f"""
                        UPDATE `{table_name}` SET subname = ?, internals = ?, grade = ?, credits = ? WHERE htno = ? AND subcode = ?
                        """, (subname, internals, grade, credits, htno, subcode))
                        update_count += 1
                else:
                    cursor.execute(f"""
                    INSERT INTO `{table_name}` (htno, subcode, subname, internals, grade, credits)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """, (htno, subcode, subname, internals, grade, credits))
                    insert_count += 1
            
            # Save the new PDF hash
            cursor.execute("INSERT INTO uploaded_pdfs (pdf_hash) VALUES (?)", (pdf_hash,))
            conn.commit()
            print(f"Database commit successful. Inserted: {insert_count}, Updated: {update_count}")

        flash(f'PDF data uploaded successfully! Inserted: {insert_count}, Updated: {update_count}', 'success')
        print("Finished /upload POST request successfully.")
    except Exception as e:
        flash(f'Error processing PDF: {str(e)}', 'danger')
        print(f"!!! ERROR during PDF processing: {e}")
        import traceback
        traceback.print_exc()
        # Ensure the temp file is removed even on error
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)
        return render_template('error.html', error_message=f"Error processing PDF: {e}"), 500

    return redirect(url_for('results_page'))

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

    conn_main = connect_db()
    conn_student = connect_student_db()

    student_name = "Unknown" # Initialize student_name

    try:
        with conn_main:
            with conn_student:
                cursor_main = conn_main.cursor()
                cursor_student = conn_student.cursor()

                # Fetch student name from the 'students' table in 'results.db'
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
                                        cursor_main.execute(
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
        return redirect(url_for('search_page')) # Redirect to search page instead of home for results

    return render_template('results.html', student_name=student_name, student_results=student_results, sgpa_results=sgpa_results, cgpa=cgpa, htnumber=htnumber)

# Global variable to store section results for download.
# CAUTION: This can be a major memory hog for many students/sections.
# For production, consider generating the Excel on-the-fly without storing all data globally,
# or using a background task/caching mechanism.
section_results = {}

@app.route('/all_students')
@login_required # Ensure only logged-in users can view all students
def all_students():
    global section_results # Declare intent to modify global variable

    semester_tables = [
        "y1_s1_results", "y1_s2_results", "y2_s1_results", "y2_s2_results",
        "y3_s1_results", "y3_s2_results", "y4_s1_results", "y4_s2_results"
    ]

    grade_values = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "COMPLE": 0}
    section_results = {} # Clear previous data to prevent stale/growing data

    try:
        student_conn = connect_student_db()
        result_conn = connect_result_db()

        with student_conn:
            with result_conn:
                student_cursor = student_conn.cursor()
                result_cursor = result_conn.cursor()

                student_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                section_tables_in_db = [table['name'] for table in student_cursor.fetchall() if table['name'] != 'students']

                for section in section_tables_in_db:
                    student_cursor.execute(f"SELECT roll_number, name FROM `{section}`")
                    students = student_cursor.fetchall()

                    section_cgpa_data = []

                    for student in students:
                        roll_number = student["roll_number"]
                        name = student["name"]

                        if "HP" not in roll_number: # Your specific filter
                            continue

                        total_cgpa_points_student = 0 # Renamed for clarity
                        total_cgpa_credits_student = 0 # Renamed for clarity

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
                        # Explicitly delete student data from memory after processing
                        del student
                        gc.collect()

                    section_results[section] = section_cgpa_data
                    # Explicitly delete section_cgpa_data if not needed immediately after loop
                    # For a global variable, this would only be done if you re-fetch on every request.
                    # Given it's a global, we keep it, but be aware of its size.

    except Exception as e:
        flash(f"Error fetching student CGPAs: {str(e)}", "danger")
        print(f"!!! ERROR fetching student CGPAs: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('home'))

    return render_template('all_students.html', section_results=section_results)

# Download option for individual section results
@app.route('/download_section_excel/<section>')
@login_required # Ensure only logged-in users can download
def download_section_excel(section):
    """Generate and download an Excel file for a specific section."""
    # Re-fetch data if section_results might be stale or too large to keep in memory globally
    # For now, relying on global, but be aware of memory implications.
    if section not in section_results:
        flash("Section data not found or not loaded. Please visit /all_students first.", "danger")
        return redirect(url_for('all_students'))

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = f"{section}_CGPA"

    ws.append(["Roll Number", "Name", "CGPA"])

    for student in section_results[section]:
        ws.append([student['roll_number'], student['name'], student['cgpa']])

    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    return Response(buffer, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f"attachment; filename={section}_cgpa.xlsx"})

# Download option for all section results
@app.route('/download_all_sections_excel')
@login_required # Ensure only logged-in users can download
def download_all_sections_excel():
    """Generate and download an Excel file for all sections."""
    # Re-fetch data if section_results might be stale or too large to keep in memory globally
    # For now, relying on global, but be aware of memory implications.
    if not section_results: # Check if global variable is empty
        flash("No student data loaded for all sections. Please visit /all_students first.", "danger")
        return redirect(url_for('all_students'))

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "All_Sections_CGPA"

    ws.append(["Section", "Roll Number", "Name", "CGPA"])

    for section, students in section_results.items():
        for student in students:
            ws.append([section, student['roll_number'], student['name'], student['cgpa']])

    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    return Response(buffer, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": "attachment; filename=all_sections_cgpa.xlsx"})

# Storing section wise student name in "student.db"
@app.route('/upload_details_excel', methods=['POST']) # Added a route for this function
@login_required # Ensure only logged-in users can upload details
def upload_details_excel():
    if 'excel_file' not in request.files:
        flash('No Excel file selected!', 'warning')
        return redirect(url_for('details_page'))

    file = request.files['excel_file']
    if file.filename == '':
        flash('No selected file.', 'warning')
        return redirect(url_for('details_page'))

    temp_excel_path = os.path.join(UPLOAD_FOLDER1, file.filename)
    try:
        file.save(temp_excel_path)
        print(f"Excel file saved to temp path: {temp_excel_path}")
    except Exception as e:
        flash(f"Error saving Excel file: {str(e)}", 'danger')
        print(f"!!! ERROR saving Excel file: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('details_page'))

    try:
        result = process_excel(temp_excel_path)
        if "message1" in result:
            flash(result["message1"], 'success')
        
        # Also process to single table if needed
        result_single = process_excel_to_single_table(temp_excel_path)
        if "message2" in result_single:
            flash(result_single["message2"], 'success')

        os.remove(temp_excel_path) # Clean up temp file
        print(f"Removed temporary Excel file: {temp_excel_path}")
        gc.collect()

    except Exception as e:
        flash(f"Error processing Excel file: {str(e)}", 'danger')
        print(f"!!! ERROR processing Excel file: {e}")
        import traceback
        traceback.print_exc()
        if os.path.exists(temp_excel_path):
            os.remove(temp_excel_path)
    
    return redirect(url_for('details_page'))


def process_excel(file_path):
    conn = connect_student_db()
    if not conn:
        return {"message1": "Failed to connect to student database."}

    with conn:
        cursor = conn.cursor()
        xls = pd.ExcelFile(file_path)
        processed_data = {}

        for sheet_name in xls.sheet_names:
            print(f"Processing Excel sheet: {sheet_name}")
            df = pd.read_excel(xls, sheet_name=sheet_name, header=None, dtype=str)
            df = df.dropna(how='all').dropna(axis=1, how="all").reset_index(drop=True)

            if df.empty or df.shape[1] < 2:
                print(f"Sheet {sheet_name} is empty or has too few columns, skipping.")
                continue

            # Limit sample data for pattern detection to reduce memory for very wide sheets
            sample_data = df.head(10).fillna("").astype(str)
            roll_col_idx = None
            name_col_idx = None

            roll_number_pattern = re.compile(r"^\d{2}HP\dA\d{2}[A-Z0-9]{2}$", re.IGNORECASE)

            for col_idx in range(sample_data.shape[1]):
                col_values = sample_data.iloc[:, col_idx].tolist()
                roll_matches = sum(bool(roll_number_pattern.match(str(val))) for val in col_values)
                name_matches = sum(bool(re.search(r"[A-Za-z]{3,}", str(val))) for val in col_values)

                if roll_matches >= 3:
                    roll_col_idx = col_idx
                elif name_matches >= 3:
                    name_col_idx = col_idx

            if roll_col_idx is not None and name_col_idx is not None:
                df_filtered = df.iloc[:, [name_col_idx, roll_col_idx]].copy()
                df_filtered.columns = ["name", "roll_number"]

                table_name = sheet_name.replace(" ", "_").replace("-", "_").lower()
                table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name)

                cursor.execute(f"""
                    CREATE TABLE IF NOT EXISTS `{table_name}` (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        roll_number TEXT UNIQUE
                    )
                """)

                # Batch insert for efficiency and lower memory overhead
                data_to_insert = []
                for _, row in df_filtered.iterrows():
                    name = str(row['name']).strip() if pd.notna(row['name']) else ""
                    roll_number = str(row['roll_number']).strip() if pd.notna(row['roll_number']) else ""
                    if name and roll_number:
                        data_to_insert.append((name, roll_number))
                
                if data_to_insert:
                    try:
                        cursor.executemany(f"INSERT OR IGNORE INTO `{table_name}` (name, roll_number) VALUES (?, ?)", data_to_insert)
                        conn.commit()
                        print(f"Inserted/Ignored {len(data_to_insert)} records into {table_name}.")
                    except sqlite3.Error as e:
                        print(f"Error inserting into {table_name}: {e}")
                
                processed_data[table_name] = df_filtered.to_dict(orient='records')
                del df_filtered # Free memory
                gc.collect()

            del df # Free memory
            gc.collect()
        
        # xls.close() # pd.ExcelFile doesn't have a close method, but it's handled by context manager or garbage collection
        del xls # Free memory
        gc.collect()

    return {"message1": "Students data for sections uploaded"}

def process_excel_to_single_table(file_path):
    conn = connect_result_db()
    if not conn:
        return {"message2": "Failed to connect to result database."}

    with conn:
        cursor = conn.cursor()
        xls = pd.ExcelFile(file_path)
        roll_number_pattern = re.compile(r"^\d{2}[A-Z]{2}\d{1,2}[A-Z0-9]+$", re.IGNORECASE)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                roll_number TEXT UNIQUE
            )
        """)

        for sheet_name in xls.sheet_names:
            print(f"Processing Excel sheet for single table: {sheet_name}")
            df = pd.read_excel(xls, sheet_name=sheet_name, header=None, dtype=str)
            df = df.dropna(how='all') # Drop rows that are entirely NaN

            if df.empty:
                print(f"Sheet {sheet_name} is empty, skipping for single table.")
                continue

            # Find columns for name and roll_number similar to process_excel
            sample_data = df.head(10).fillna("").astype(str)
            roll_col_idx = None
            name_col_idx = None

            for col_idx in range(sample_data.shape[1]):
                col_values = sample_data.iloc[:, col_idx].tolist()
                roll_matches = sum(bool(roll_number_pattern.match(str(val))) for val in col_values)
                name_matches = sum(bool(re.search(r"[A-Za-z]{3,}", str(val))) for val in col_values)

                if roll_matches >= 3:
                    roll_col_idx = col_idx
                elif name_matches >= 3:
                    name_col_idx = col_idx
            
            if roll_col_idx is not None and name_col_idx is not None:
                df_filtered = df.iloc[:, [name_col_idx, roll_col_idx]].copy()
                df_filtered.columns = ["name", "roll_number"]
                df_filtered = df_filtered.dropna(subset=["name", "roll_number"]) # Ensure no NaNs in critical columns

                data_to_insert = []
                for _, row in df_filtered.iterrows():
                    name = str(row['name']).strip()
                    roll_number = str(row['roll_number']).strip()
                    if name and roll_number:
                        data_to_insert.append((name, roll_number))
                
                if data_to_insert:
                    try:
                        cursor.executemany("INSERT OR IGNORE INTO students (name, roll_number) VALUES (?, ?)", data_to_insert)
                        conn.commit()
                        print(f"Inserted/Ignored {len(data_to_insert)} records into 'students' table from sheet {sheet_name}.")
                    except sqlite3.Error as e:
                        print(f"Error inserting into 'students' table from sheet {sheet_name}: {e}")
                
                del df_filtered # Free memory
                gc.collect()

            del df # Free memory
            gc.collect()
        
        del xls # Free memory
        gc.collect()

    return {"message2": "Students data for single table uploaded"}


# --- Mail Test Route (for debugging email setup) ---
@app.route('/test-mail')
def test_mail():
    try:
        # Use an environment variable for the recipient email in production
        recipient_email = os.environ.get('TEST_MAIL_RECIPIENT', 'your_email@example.com')
        msg = Message("Hello from Flask", sender=app.config['MAIL_USERNAME'], recipients=[recipient_email])
        msg.body = "This is a test email from your Flask application deployed on Render."
        mail.send(msg)
        return "Email sent successfully! Check your inbox."
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Error sending email: {e}. Check Render logs for details on Flask-Mail configuration."


# --- Run the app ---
if __name__ == '__main__':
    # This block is for local development only.
    # When deployed with Gunicorn (as recommended for Render), this block won't run.
    print(f"Flask app running in development mode. Uploads will go to: {app.config['UPLOAD_FOLDER']}")
    initialize_all_dbs() # Ensure databases are initialized for local dev
    app.run(debug=True, host='0.0.0.0', port=5000)
