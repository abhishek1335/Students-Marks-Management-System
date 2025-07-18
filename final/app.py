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
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from config import connect_auth_db, connect_db, connect_result_db, connect_student_db, initialize_all_dbs

# Constants
UPLOAD_FOLDER = "uploads"
UPLOAD_FOLDER1 = "uploads1"
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB
GRADE_VALUES = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "COMPLE": 0}
SEMESTER_TABLES = [f"y{year}_s{sem}_results" for year in range(1, 5) for sem in range(1, 3)]
ROLL_NUMBER_PATTERN = re.compile(r"^\d{2}HP\dA\d{2}[A-Z0-9]{2}$", re.IGNORECASE)
DEFAULT_SECRET_KEY = 'your_secret_key_from_env'

# Initialize Flask app
app = Flask(__name__)
app.config.update({
    'SECRET_KEY': os.environ.get('SECRET_KEY', DEFAULT_SECRET_KEY),
    'UPLOAD_FOLDER': UPLOAD_FOLDER,
    'MAX_CONTENT_LENGTH': MAX_CONTENT_LENGTH,
    'MAIL_SERVER': os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
    'MAIL_PORT': int(os.environ.get('MAIL_PORT', 587)),
    'MAIL_USE_TLS': os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true',
    'MAIL_USE_SSL': os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true',
    'MAIL_USERNAME': os.environ.get('MAIL_USERNAME', 'darkplayer1335@gmail.com'),
    'MAIL_PASSWORD': os.environ.get('MAIL_PASSWORD', 'uqic wxbn pnfe khqt')
})

# Ensure upload directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER1, exist_ok=True)

# Initialize extensions
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Thread pool for background tasks
executor = ThreadPoolExecutor(4)

# --- Decorators ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("Unauthorized access!", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Functions ---
def generate_token(length=6):
    """Generate a random alphanumeric token."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_pdf_hash(file_path, chunk_size=4096):
    """Generate SHA256 hash for a file in chunks to conserve memory."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def clean_int_data(value):
    """Clean integer data from various string formats."""
    if pd.isna(value) or str(value).strip() in ('---', '', 'N/A', 'nan'):
        return 0
    try:
        return int(float(str(value).strip()))
    except ValueError:
        return 0

def clean_float_data(value):
    """Clean float data from various string formats."""
    if pd.isna(value) or str(value).strip() in ('---', '', 'N/A', 'nan'):
        return 0.0
    try:
        return float(str(value).strip()))
    except ValueError:
        return 0.0

# --- User Class ---
class User(UserMixin):
    __slots__ = ['id', 'username', 'email', 'is_admin']  # Optimize memory usage
    
    def __init__(self, id, username, email, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    """Load user from database for Flask-Login."""
    with connect_auth_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, is_admin FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
    
    return User(**user_data) if user_data else None

# --- Authentication Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            with connect_auth_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
                    (username, email, hashed_password, 0)
                )
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

        with connect_auth_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, password, is_admin FROM users WHERE email=?",
                (email,)
            user = cursor.fetchone()

        if not user:
            flash("User not found!", "danger")
            return redirect(url_for('login'))

        if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            user_obj = User(user['id'], user['username'], user['email'], bool(user['is_admin']))
            login_user(user_obj)
            
            session.update({
                'user_id': user['id'],
                'is_admin': bool(user['is_admin'])
            })
            
            flash("Login successful!", "success")
            return redirect(url_for('admin_dashboard' if user_obj.is_admin else 'dashboard'))
        
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
    return render_template('dashboard.html')

@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        with connect_auth_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
            user = cursor.fetchone()

        if user:
            token = generate_token()
            session.update({
                'reset_token': token,
                'reset_email': email
            })

            msg = Message(
                "Password Reset",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"Your password reset code is: {token}"
            
            try:
                mail.send(msg)
                flash("Check your email for the reset code!", "info")
                return redirect(url_for('reset_password'))
            except Exception as e:
                app.logger.error(f"Email sending error: {e}", exc_info=True)
                flash(f"Error sending email: {str(e)}", "danger")
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
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            with connect_auth_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET password=? WHERE email=?",
                    (hashed_password, session['reset_email'])
                )
                conn.commit()

            session.pop('reset_token', None)
            session.pop('reset_email', None)
            
            flash("Password reset successful! You can now log in.", "success")
            return redirect(url_for('login'))
        
        flash("Invalid reset code!", "danger")
    
    return render_template('reset_password.html')

@app.route('/create-admin', methods=['GET', 'POST'])
@login_required
@admin_required
def create_admin():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            with connect_auth_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
                    (username, email, hashed_password, 1)
                )
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

@app.route('/upload', methods=['POST'])
@login_required
def upload_pdf():
    if 'pdf_file' not in request.files:
        flash('No file selected', 'yellow')
        return redirect(url_for('results_page'))

    file = request.files['pdf_file']
    year = request.form.get('year')
    semester = request.form.get('semester')

    if not all([file.filename, year, semester]):
        flash('Missing file, year, or semester input', 'yellow')
        return redirect(url_for('results_page'))

    # Sanitize table name
    table_name = f"y{year}_s{semester}_results"
    table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name)

    temp_pdf_path = os.path.join(UPLOAD_FOLDER, file.filename)
    
    try:
        file.save(temp_pdf_path)
        pdf_hash = generate_pdf_hash(temp_pdf_path)
        
        with connect_db() as conn:
            cursor = conn.cursor()
            
            # Check for duplicate PDF
            cursor.execute("SELECT pdf_hash FROM uploaded_pdfs WHERE pdf_hash = ?", (pdf_hash,))
            if cursor.fetchone():
                flash("This PDF has already been uploaded. No changes made.", 'warning')
                os.remove(temp_pdf_path)
                return redirect(url_for('results_page'))

            # Create tables if not exists
            cursor.executescript(f"""
                CREATE TABLE IF NOT EXISTS uploaded_pdfs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pdf_hash TEXT UNIQUE
                );
                
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

            # Process PDF with tabula
            tables = tabula.read_pdf(
                temp_pdf_path,
                pages="all",
                multiple_tables=True,
                stream=True
            )
            
            # Process tables in chunks
            processed_data = []
            for table_df in tables:
                if table_df.empty:
                    continue
                
                # Standardize and clean data
                table_df.columns = [col.strip().replace('.', '').capitalize() for col in table_df.columns]
                if "Sno" in table_df.columns:
                    table_df = table_df.drop(columns=["Sno"])
                
                expected_columns = ["Htno", "Subcode", "Subname", "Internals", "Grade", "Credits"]
                df_filtered = table_df[[col for col in table_df.columns if col in expected_columns]].copy()
                
                # Ensure all columns are present
                for col in expected_columns:
                    if col not in df_filtered.columns:
                        df_filtered[col] = None
                
                df_filtered = df_filtered[expected_columns]
                df_filtered = df_filtered.dropna(subset=["Htno", "Subcode"])
                df_filtered = df_filtered[df_filtered["Htno"].astype(str).str.lower() != "htno"]
                
                # Clean data
                df_filtered["Internals"] = df_filtered["Internals"].apply(clean_int_data)
                df_filtered["Credits"] = df_filtered["Credits"].apply(clean_float_data)
                
                processed_data.extend(df_filtered.to_records(index=False).tolist())

            # Batch insert/update
            insert_count = 0
            update_count = 0
            
            for row in processed_data:
                htno, subcode, subname, internals, grade, credits = row
                htno = str(htno).strip()
                subcode = str(subcode).strip()
                subname = str(subname).strip()
                grade = str(grade).strip()
                
                # Check existing record
                cursor.execute(
                    f"SELECT grade, credits FROM `{table_name}` WHERE htno = ? AND subcode = ?",
                    (htno, subcode)
                )
                existing = cursor.fetchone()
                
                if existing:
                    existing_grade, existing_credits = existing
                    new_rank = GRADE_VALUES.get(grade.upper(), -1)
                    old_rank = GRADE_VALUES.get(existing_grade.upper(), -1)
                    
                    if (new_rank > old_rank or 
                        (old_rank <= 0 and new_rank > 0) or 
                        (new_rank == old_rank and credits != existing_credits)):
                        cursor.execute(
                            f"""UPDATE `{table_name}` 
                            SET subname=?, internals=?, grade=?, credits=? 
                            WHERE htno=? AND subcode=?""",
                            (subname, internals, grade, credits, htno, subcode)
                        )
                        update_count += 1
                else:
                    cursor.execute(
                        f"""INSERT INTO `{table_name}` 
                        (htno, subcode, subname, internals, grade, credits) 
                        VALUES (?, ?, ?, ?, ?, ?)""",
                        (htno, subcode, subname, internals, grade, credits)
                    )
                    insert_count += 1
            
            # Save PDF hash
            cursor.execute("INSERT INTO uploaded_pdfs (pdf_hash) VALUES (?)", (pdf_hash,))
            conn.commit()
            
            flash(
                f'PDF data uploaded successfully! Inserted: {insert_count}, Updated: {update_count}',
                'success'
            )
    
    except Exception as e:
        app.logger.error(f"Error processing PDF: {e}", exc_info=True)
        flash(f'Error processing PDF: {str(e)}', 'danger')
        return render_template('error.html', error_message=f"Error processing PDF: {e}"), 500
    
    finally:
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)
        gc.collect()
    
    return redirect(url_for('results_page'))

@app.route('/get_results', methods=['POST'])
def get_results():
    htnumber = request.form.get('htno')
    if len(htnumber) != 10:
        flash('Invalid roll number', 'warning')
        return redirect(url_for('search_page'))

    student_results = {}
    sgpa_results = {}
    total_cgpa_points = 0
    total_cgpa_credits = 0
    student_name = "Unknown"

    try:
        with connect_db() as conn_main, connect_student_db() as conn_student:
            cursor_main = conn_main.cursor()
            cursor_student = conn_student.cursor()

            # Get student name
            cursor_main.execute(
                "SELECT name FROM students WHERE roll_number = ? LIMIT 1",
                (htnumber,)
            )
            if name_data := cursor_main.fetchone():
                student_name = name_data['name']

            # Process each semester table
            for table in SEMESTER_TABLES:
                try:
                    cursor_main.execute(
                        f"SELECT subname, grade, credits FROM `{table}` WHERE htno = ?",
                        (htnumber,)
                    )
                    results = cursor_main.fetchall()
                    student_results[table] = results if results else "No Data"

                    if results:
                        sem_points = 0
                        sem_credits = 0

                        for row in results:
                            subname = row['subname']
                            grade = row['grade']
                            credits = row['credits']

                            if grade.upper() in ("F", "MP", "ABSENT") or credits == 0.0:
                                cursor_main.execute(
                                    f"""SELECT credits FROM `{table}` 
                                    WHERE subname = ? AND grade NOT IN ('F', 'MP', 'ABSENT', 'COMPLE') 
                                    LIMIT 1""",
                                    (subname,)
                                )
                                if credit_data := cursor_main.fetchone():
                                    credits = credit_data['credits']
                                else:
                                    credits = 0

                            grade_point = GRADE_VALUES.get(grade.upper(), 0)
                            sem_credits += credits
                            sem_points += grade_point * credits

                        if sem_credits > 0:
                            sgpa_results[table] = round(sem_points / sem_credits, 2)
                            total_cgpa_points += sem_points
                            total_cgpa_credits += sem_credits
                        else:
                            sgpa_results[table] = "No SGPA"
                    else:
                        sgpa_results[table] = "No Data"

                except sqlite3.OperationalError:
                    app.logger.info(f"Skipping missing table {table} for {htnumber}")
                    student_results[table] = "No Data"
                    sgpa_results[table] = "No Data"
                except Exception as e:
                    app.logger.error(f"Error in {table} processing: {e}", exc_info=True)
                    student_results[table] = "Error"
                    sgpa_results[table] = "Error"

        cgpa = round(total_cgpa_points / total_cgpa_credits, 2) if total_cgpa_credits > 0 else "No CGPA"
    
    except Exception as e:
        app.logger.error(f"Error fetching results: {e}", exc_info=True)
        flash(f"Error fetching student results: {str(e)}", "danger")
        return redirect(url_for('search_page'))

    return render_template(
        'results.html',
        student_name=student_name,
        student_results=student_results,
        sgpa_results=sgpa_results,
        cgpa=cgpa,
        htnumber=htnumber
    )

# --- Student Data Processing ---
@app.route('/upload_details_excel', methods=['POST'])
@login_required
def upload_details_excel():
    if 'excel_file' not in request.files:
        flash('No Excel file selected!', 'warning')
        return redirect(url_for('details_page'))

    file = request.files['excel_file']
    if not file.filename:
        flash('No selected file.', 'warning')
        return redirect(url_for('details_page'))

    temp_path = os.path.join(UPLOAD_FOLDER1, file.filename)
    
    try:
        file.save(temp_path)
        
        # Process in background
        executor.submit(process_excel_files, temp_path)
        
        flash("Excel file upload started. Data will be processed in the background.", "info")
    
    except Exception as e:
        app.logger.error(f"Error saving Excel: {e}", exc_info=True)
        flash(f"Error saving Excel file: {str(e)}", 'danger')
    
    return redirect(url_for('details_page'))

def process_excel_files(file_path):
    """Process Excel file in background."""
    try:
        # Process to section tables
        with connect_student_db() as conn:
            process_excel_to_sections(file_path, conn)
        
        # Process to single table
        with connect_result_db() as conn:
            process_excel_to_single_table(file_path, conn)
        
        os.remove(file_path)
        gc.collect()
    
    except Exception as e:
        app.logger.error(f"Error processing Excel: {e}", exc_info=True)
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

def process_excel_to_sections(file_path, conn):
    """Process Excel file to section tables."""
    xls = pd.ExcelFile(file_path)
    cursor = conn.cursor()
    
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(xls, sheet_name, header=None, dtype=str)
        df = df.dropna(how='all').dropna(axis=1, how="all")
        
        if df.empty or df.shape[1] < 2:
            continue
        
        # Find name and roll number columns
        sample = df.head(10).fillna("").astype(str)
        roll_col, name_col = None, None
        
        for col in range(sample.shape[1]):
            col_data = sample.iloc[:, col].tolist()
            roll_matches = sum(bool(ROLL_NUMBER_PATTERN.match(str(x))) for x in col_data)
            name_matches = sum(bool(re.search(r"[A-Za-z]{3,}", str(x))) for x in col_data)
            
            if roll_matches >= 3:
                roll_col = col
            elif name_matches >= 3:
                name_col = col
        
        if roll_col is not None and name_col is not None:
            df_filtered = df.iloc[:, [name_col, roll_col]].copy()
            df_filtered.columns = ["name", "roll_number"]
            df_filtered = df_filtered.dropna(subset=["name", "roll_number"])
            
            table_name = re.sub(r'[^a-zA-Z0-9_]', '', sheet_name.lower().replace(" ", "_"))
            
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS `{table_name}` (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    roll_number TEXT UNIQUE
                )
            """)
            
            data = [
                (str(row['name']).strip(), str(row['roll_number']).strip())
                for _, row in df_filtered.iterrows()
                if str(row['name']).strip() and str(row['roll_number']).strip()
            ]
            
            if data:
                cursor.executemany(
                    f"INSERT OR IGNORE INTO `{table_name}` (name, roll_number) VALUES (?, ?)",
                    data
                )
                conn.commit()

def process_excel_to_single_table(file_path, conn):
    """Process Excel file to single students table."""
    xls = pd.ExcelFile(file_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            roll_number TEXT UNIQUE
        )
    """)
    
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(xls, sheet_name, header=None, dtype=str)
        df = df.dropna(how='all')
        
        if df.empty:
            continue
        
        # Find name and roll number columns
        sample = df.head(10).fillna("").astype(str)
        roll_col, name_col = None, None
        
        for col in range(sample.shape[1]):
            col_data = sample.iloc[:, col].tolist()
            roll_matches = sum(bool(ROLL_NUMBER_PATTERN.match(str(x))) for x in col_data)
            name_matches = sum(bool(re.search(r"[A-Za-z]{3,}", str(x))) for x in col_data)
            
            if roll_matches >= 3:
                roll_col = col
            elif name_matches >= 3:
                name_col = col
        
        if roll_col is not None and name_col is not None:
            df_filtered = df.iloc[:, [name_col, roll_col]].copy()
            df_filtered.columns = ["name", "roll_number"]
            df_filtered = df_filtered.dropna(subset=["name", "roll_number"])
            
            data = [
                (str(row['name']).strip(), str(row['roll_number']).strip())
                for _, row in df_filtered.iterrows()
                if str(row['name']).strip() and str(row['roll_number']).strip()
            ]
            
            if data:
                cursor.executemany(
                    "INSERT OR IGNORE INTO students (name, roll_number) VALUES (?, ?)",
                    data
                )
                conn.commit()

# --- Run the app ---
if __name__ == '__main__':
    initialize_all_dbs()
    app.run(debug=True, host='0.0.0.0', port=5000)
