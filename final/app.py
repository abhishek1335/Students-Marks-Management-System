from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, Response
import openpyxl
import io
import bcrypt
import pandas as pd
import tabula

import hashlib
import os
import re
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from config import connect_auth_db, connect_db, connect_result_db, connect_student_db
import random
import string
from flask_mail import Mail, Message
import sqlite3 # Import sqlite3 directly for type hints and clarity, though config handles the connection
from config import connect_auth_db, connect_db, connect_result_db, connect_student_db, initialize_all_dbs 
import random
import string
from flask_mail import Mail, Message
import sqlite3


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Used for session management
mail = Mail(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Use TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'darkplayer1335@gmail.com'
app.config['MAIL_PASSWORD'] = 'uqic wxbn pnfe khqt'

@app.route('/test-mail')
def test_mail():
    try:
        msg = Message("Hello from Flask", sender="darkplayer1335@gmail.com", recipients=["your_email@example.com"])
        msg.body = "This is a test email from Flask."
        mail.send(msg)
        return "Email sent successfully!"
    except Exception as e:
        return f"Error: {e}"

def generate_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

login_manager = LoginManager()
login_manager.login_view = 'login'  # Redirects unauthorized users to login page
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, username, email, is_admin=False): # Added is_admin
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin # Store admin status

@login_manager.user_loader
def load_user(user_id):
    conn = connect_auth_db()
    with conn: # Use 'with' statement for automatic closing
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, is_admin FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['email'], bool(user_data['is_admin']))
    return None

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

        # user['password'] is already a string due to .decode('utf-8') during registration
        if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            # Authenticate user with Flask-Login
            flask_login_user = User(user['id'], user['username'], user['email'], bool(user['is_admin']))
            login_user(flask_login_user)

            session['user_id'] = user['id']
            session['is_admin'] = bool(user['is_admin'])

            print(session.get("user_id"))  # Debugging
            print(session.get("is_admin"))
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
@login_required # Use Flask-Login's @login_required
def dashboard():
    print("Session user_id:", session.get("user_id"))  # Debugging
    return render_template('dashboard.html')

@app.route('/admin_dashboard')
@login_required # Use Flask-Login's @login_required
def admin_dashboard():
    print("Session user_id:", session.get("user_id"))  # Debugging
    print("Session is_admin:", session.get("is_admin"))  # Debugging
    if not current_user.is_admin: # Check admin status using current_user
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

                msg = Message("Password Reset", sender="darkplayer1335@gmail.com", recipients=[email])
                msg.body = f"Your password reset code is: {token}"
                mail.send(msg)

                flash("Check your email for the reset code!", "info")
                return redirect(url_for('reset_password'))
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

        if entered_token == session['reset_token']:
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            conn = connect_auth_db()
            with conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_new_password, session['reset_email']))
                conn.commit()

            session.pop('reset_token')
            session.pop('reset_email')
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

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

UPLOAD_FOLDER1 = "uploads1"
os.makedirs(UPLOAD_FOLDER1, exist_ok=True)

def generate_pdf_hash(file_path):
    """Generate SHA256 hash for the uploaded PDF."""
    with open(file_path, "rb") as f:
        pdf_data = f.read()
    return hashlib.sha256(pdf_data).hexdigest()

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
def upload_pdf():
    if 'pdf_file' not in request.files:
        flash('No file selected', 'yellow')
        return redirect(url_for('results_page'))

    file = request.files['pdf_file']
    year = request.form.get('year')
    semester = request.form.get('semester')

    if file.filename == '' or not year or not semester:
        flash('Missing file, year, or semester input', 'yellow')
        return redirect(url_for('results_page'))

    # Sanitize table name (important for SQLite which is more strict than MySQL with identifiers)
    table_name = f"y{year}_s{semester}_results"
    table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name) # Remove any non-alphanumeric/underscore chars

    temp_pdf_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(temp_pdf_path)

    try:
        conn = connect_db()
        with conn: # Use 'with' statement for automatic closing and committing/rolling back
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
                os.remove(temp_pdf_path)
                return redirect(url_for('results_page'))

            # Create results table dynamically if not exists
            # SQLite uses INTEGER PRIMARY KEY AUTOINCREMENT
            cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS `{table_name}` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                htno TEXT,
                subcode TEXT,
                subname TEXT,
                internals INTEGER,
                grade TEXT,
                credits REAL,
                UNIQUE(htno, subcode) -- UNIQUE constraint
            );
            """)

            # Extract tables from PDF
            tables = tabula.read_pdf(temp_pdf_path, pages="all", multiple_tables=True, stream=True)
            os.remove(temp_pdf_path)  # Remove temp file after reading
            df = pd.concat(tables, ignore_index=True)

            # Define expected columns
            # Ensure column names are consistent before dropping/reassigning
            df.columns = [col.strip().replace('.', '').capitalize() for col in df.columns]

            if "Sno" in df.columns:
                df = df.drop(columns=["Sno"])

            expected_columns_template = ["Htno", "Subcode", "Subname", "Internals", "Grade", "Credits"]
            # Rename columns to match expected template if necessary
            # This is a bit more robust than just slicing, especially if columns are reordered
            current_columns = [col for col in df.columns if col in expected_columns_template]
            df = df[current_columns] # Select only relevant columns
            # Ensure all expected columns are present, fill with NaN if not (though tabula usually gets them)
            for col in expected_columns_template:
                if col not in df.columns:
                    df[col] = None
            df = df[expected_columns_template] # Reorder to ensure correct insertion order

            df = df.dropna()
            df = df[df["Htno"].astype(str).str.lower() != "htno"] # Convert to string for .str accessor

            def clean_int_data(value):
                if pd.isna(value) or str(value).strip() in ('---', '', 'N/A'):
                    return 0
                try:
                    return int(float(str(value))) # Handle cases where it might be a float string
                except ValueError:
                    return 0

            def clean_float_data(value):
                if pd.isna(value) or str(value).strip() in ('---', '', 'N/A'):
                    return 0.0
                try:
                    return float(str(value))
                except ValueError:
                    return 0.0

            df["Internals"] = df["Internals"].apply(clean_int_data)
            df["Credits"] = df["Credits"].apply(clean_float_data)

            # Insert or update records
            for _, row in df.iterrows():
                htno = str(row["Htno"]).strip() # Ensure string
                subcode = str(row["Subcode"]).strip() # Ensure string
                subname = str(row["Subname"]).strip() # Ensure string
                internals = int(row["Internals"])
                grade = str(row["Grade"]).strip() # Ensure string
                credits = float(row["Credits"])

                cursor.execute(f"SELECT grade, credits FROM `{table_name}` WHERE htno = ? AND subcode = ?", (htno, subcode))
                existing_record = cursor.fetchone()

                if existing_record:
                    existing_grade, existing_credits = existing_record
                    # More robust grade comparison: assuming higher ordinal value means 'worse' grade (e.g., A < B < C < F)
                    # This logic should be carefully reviewed based on your grading system.
                    # For a common system (A+ > A > B > C > D > E > F/ABSENT/MP), lower ord() is better.
                    # Let's refine: If new grade is better OR current is a placeholder, update.
                    grade_rank = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "NO CHANGE": 100} # Assign ranks
                    # Prioritize the new grade if it's better or if the old one was a placeholder
                    if (grade_rank.get(grade.upper(), 0) > grade_rank.get(existing_grade.upper(), 0) and
                        grade.upper() not in ["NO CHANGE", "ABSENT", "MP"]):
                        cursor.execute(f"""
                        UPDATE `{table_name}` SET grade = ?, credits = ? WHERE htno = ? AND subcode = ?
                        """, (grade, credits, htno, subcode))
                    elif existing_grade.upper() in ["NO CHANGE", "ABSENT", "MP"] and grade.upper() not in ["NO CHANGE", "ABSENT", "MP"]:
                        cursor.execute(f"""
                        UPDATE `{table_name}` SET grade = ?, credits = ? WHERE htno = ? AND subcode = ?
                        """, (grade, credits, htno, subcode))
                else:
                    cursor.execute(f"""
                    INSERT INTO `{table_name}` (htno, subcode, subname, internals, grade, credits)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """, (htno, subcode, subname, internals, grade, credits))

            # Save the new PDF hash
            cursor.execute("INSERT INTO uploaded_pdfs (pdf_hash) VALUES (?)", (pdf_hash,))
            conn.commit()

        flash('PDF data uploaded successfully!', 'success')
    except Exception as e:
        flash(f'Error processing PDF: {str(e)}', 'danger')
        # Ensure the temp file is removed even on error
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)

    return redirect(url_for('results_page'))

# Searching student results using roll number
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

    conn_main = connect_db() # Connection for main results DB
    conn_student = connect_student_db() # Connection for student details DB

    with conn_main:
        with conn_student:
            cursor_main = conn_main.cursor()
            cursor_student = conn_student.cursor()

            # Fetch student name from the 'students' table in 'results.db'
            cursor_main.execute("SELECT name FROM students WHERE roll_number = ? LIMIT 1", (htnumber,))
            student_name_data = cursor_main.fetchone()
            global student_name # This makes it a global variable, consider passing it to render_template
            student_name = student_name_data['name'] if student_name_data else "Unknown"

            for table in semester_tables:
                try:
                    cursor_main.execute(f"SELECT subname, grade, credits FROM `{table}` WHERE htno = ?", (htnumber,))
                    results = cursor_main.fetchall()
                    student_results[table] = results if results else "No Data"

                    if results:
                        total_credits = 0
                        total_grade_points = 0

                        for row in results:
                            subname = row['subname']
                            grade = row['grade']
                            credits = row['credits'] # This will be the direct credit from the table

                            if grade.upper() in ("F", "MP", "ABSENT") or credits == 0.0:
                                # Fetch credits from passed students for failed subjects
                                try:
                                    cursor_main.execute(
                                        f"SELECT credits FROM `{table}` WHERE subname = ? AND grade NOT IN ('F', 'MP', 'ABSENT', 'COMPLE') LIMIT 1",
                                        (subname,)
                                    )
                                    fetched_credit_data = cursor_main.fetchone()
                                    if fetched_credit_data and fetched_credit_data['credits'] is not None:
                                        credits = fetched_credit_data['credits']
                                    else:
                                        credits = 0 # Default to 0 if no valid credit found for failed subject
                                except sqlite3.Error as fetch_error:
                                    print(f"Error fetching credits for {subname}: {fetch_error}")
                                    credits = 0

                            grade_point = grade_values.get(grade.upper(), 0) # Ensure grade is uppercase for dict lookup
                            total_credits += credits
                            total_grade_points += grade_point * credits

                        if total_credits > 0:
                            sgpa_results[table] = round(total_grade_points / total_credits, 2)
                        else:
                            sgpa_results[table] = "No SGPA"

                        # Update CGPA calculation
                        if total_credits > 0:
                            total_cgpa_points += total_grade_points
                            total_cgpa_credits += total_credits
                    else:
                        sgpa_results[table] = "No Data"

                except sqlite3.Error as table_error:
                    print(f"Error processing table {table}: {table_error}")
                    student_results[table] = "No Data"
                    sgpa_results[table] = "No Data"

            cgpa = round(total_cgpa_points / total_cgpa_credits, 2) if total_cgpa_credits > 0 else "No CGPA"

    return render_template('results.html', student_name=student_name, student_results=student_results, sgpa_results=sgpa_results, cgpa=cgpa, htnumber=htnumber)

# Fetching all student results
@app.route('/all_students')
def all_students():
    global section_results # Ensure this is accessible if used globally for download
    semester_tables = [
        "y1_s1_results", "y1_s2_results", "y2_s1_results", "y2_s2_results",
        "y3_s1_results", "y3_s2_results", "y4_s1_results", "y4_s2_results"
    ]

    grade_values = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "COMPLE": 0}
    section_results = {}

    try:
        student_conn = connect_student_db()
        result_conn = connect_result_db()

        with student_conn:
            with result_conn:
                student_cursor = student_conn.cursor()
                result_cursor = result_conn.cursor()

                # Get all section tables from student_db
                # In SQLite, you query sqlite_master for table names
                student_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                # Filter out the 'students' table if it's in student_db (it's in results.db currently)
                section_tables_in_db = [table['name'] for table in student_cursor.fetchall() if table['name'] != 'students']


                for section in section_tables_in_db:
                    student_cursor.execute(f"SELECT roll_number, name FROM `{section}`")
                    students = student_cursor.fetchall()

                    section_cgpa_data = []

                    for student in students:
                        roll_number = student["roll_number"]
                        name = student["name"]

                        # You had a specific "HP" check, keeping it
                        if "HP" not in roll_number:
                            continue

                        total_cgpa_points = 0
                        total_cgpa_credits = 0

                        for table in semester_tables:
                            try:
                                result_cursor.execute(
                                    f"SELECT subname, grade, credits FROM `{table}` WHERE htno = ?", (roll_number,)
                                )
                                results = result_cursor.fetchall()

                                if results:
                                    total_credits = 0
                                    total_grade_points = 0

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
                                        total_credits += credits
                                        total_grade_points += grade_point * credits

                                    if total_credits > 0:
                                        total_cgpa_points += total_grade_points
                                        total_cgpa_credits += total_credits

                            except sqlite3.OperationalError: # Catch specific error for missing table
                                print(f"Skipping missing table {table} for roll number {roll_number}")


                        cgpa = round(total_cgpa_points / total_cgpa_credits, 2) if total_cgpa_credits > 0 else "No CGPA"

                        section_cgpa_data.append({
                            "roll_number": roll_number,
                            "name": name,
                            "cgpa": cgpa
                        })

                    section_results[section] = section_cgpa_data

    except Exception as e:
        flash(f"Error fetching student CGPAs: {str(e)}", "danger")
        return redirect(url_for('home'))

    return render_template('all_students.html', section_results=section_results)

# Download option for individual section results
@app.route('/download_section_excel/<section>')
def download_section_excel(section):
    """Generate and download an Excel file for a specific section."""
    if section not in section_results:
        flash("Section data not found!", "danger")
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
def download_all_sections_excel():
    """Generate and download an Excel file for all sections."""
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
def process_excel(file_path):
    conn = connect_student_db()
    if not conn:
        return {"message1": "Failed to connect to student database."}

    with conn: # Use with statement
        cursor = conn.cursor()
        xls = pd.ExcelFile(file_path)
        processed_data = {}

        for sheet_name in xls.sheet_names:
            df = pd.read_excel(xls, sheet_name=sheet_name, header=None, dtype=str)
            df = df.dropna(how='all').dropna(axis=1, how="all").reset_index(drop=True)

            if df.shape[1] < 2:
                continue

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
                df = df.iloc[:, [name_col_idx, roll_col_idx]]
                df.columns = ["name", "roll_number"]

                table_name = sheet_name.replace(" ", "_").replace("-", "_").lower()
                table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name) # Sanitize table name

                cursor.execute(f"""
                    CREATE TABLE IF NOT EXISTS `{table_name}` (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        roll_number TEXT UNIQUE
                    )
                """)

                for _, row in df.iterrows():
                    name = str(row['name']).strip() if pd.notna(row['name']) else ""
                    roll_number = str(row['roll_number']).strip() if pd.notna(row['roll_number']) else ""

                    if not name or not roll_number:
                        continue
                    try:
                        cursor.execute(f"INSERT OR IGNORE INTO `{table_name}` (name, roll_number) VALUES (?, ?)",
                                       (name, roll_number))
                    except sqlite3.Error as e:
                        print(f"Error inserting into {table_name}: {e}") # Log specific error
                conn.commit() # Commit after each sheet's insertions
                processed_data[table_name] = df.to_dict(orient='records')

    return {"message1": "Students data for sections uploaded"}

# Storing student names in "results.db" into single table named 'students'
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
            df = pd.read_excel(xls, sheet_name=sheet_name, header=None, dtype=str)
            df = df.dropna(how='all').dropna(axis=1, how="all").reset_index(drop=True)

            if df.shape[1] < 2:
                continue

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
                df = df.iloc[:, [name_col_idx, roll_col_idx]]
                df.columns = ["name", "roll_number"]

                for _, row in df.iterrows():
                    name = str(row['name']).strip() if pd.notna(row['name']) else ""
                    roll_number = str(row['roll_number']).strip() if pd.notna(row['roll_number']) else ""
                    if not name or not roll_number:
                        continue
                    try:
                        cursor.execute("""
                            INSERT OR IGNORE INTO students (name, roll_number) VALUES (?, ?)
                        """, (name, roll_number))
                    except sqlite3.Error as e:
                        print(f"Error inserting into students table: {e}") # Log specific error
        conn.commit() # Commit once after all sheets for this function
    return {"message2": "Students data successfully uploaded into name table"}

# Function to upload student details into 2 databases
@app.route("/upload1", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        flash("No file part", "danger")
        return redirect(url_for('details_page'))

    file = request.files["file"]

    if file.filename == "":
        flash("No selected file", "warning")
        return redirect(url_for('details_page'))

    if file:
        file_path = os.path.join(UPLOAD_FOLDER1, file.filename)
        file.save(file_path)
        try:
            response1 = process_excel(file_path)
            response2 = process_excel_to_single_table(file_path)
            flash(response1["message1"], 'success')
            flash(response2["message2"], 'success')
        except Exception as e:
            flash(f"Error during file processing: {str(e)}", "danger")
        finally:
            if os.path.exists(file_path):
                os.remove(file_path) # Clean up the uploaded file

        return render_template("upload_student_details.html")
with app.app_context():
    initialize_all_dbs()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Render sets this PORT
    app.run(host='0.0.0.0', port=port, debug=True)
