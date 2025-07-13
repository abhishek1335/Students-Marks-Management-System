from flask import Flask, jsonify, render_template, request, redirect, url_for, flash,session
from flask import Response
import openpyxl
import io
import bcrypt
import pandas as pd
import tabula
import pymysql
import hashlib
import os
import re
from flask import Flask, render_template, request, redirect, url_for, flash
import pymysql
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from config import connect_auth_db,connect_db,connect_result_db,connect_student_db
import random
import string
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Used for session management
mail = Mail(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Use TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'darkplayer1335@gmail.com'
app.config['MAIL_PASSWORD'] = 'uqic wxbn pnfe khqt'  # (Double-check this!)

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
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = connect_auth_db()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
    conn.close()
    return User(user['id'], user['username'], user['email']) if user else None



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = connect_auth_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", 
                       (username, email, hashed_password))
        conn.commit()
        conn.close()

        flash("Account created! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = connect_auth_db()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            flash("User not found!", "danger")
            return redirect(url_for('login'))

        if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
           

            print(session.get("user_id"))  # Debugging
            print(session.get("is_admin"))
            flash("Login successful!", "success")
            return redirect(url_for('admin_dashboard' if user['is_admin'] else 'dashboard'))
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
def dashboard():
    print("Session user_id:", session.get("user_id"))  # Debugging
    if "user_id" not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('login'))
    return render_template('dashboard.html') 

@app.route('/admin_dashboard')
def admin_dashboard():
    print("Session user_id:", session.get("user_id"))  # Debugging
    print("Session is_admin:", session.get("is_admin"))  # Debugging
    if "user_id" not in session or not session.get("is_admin"):
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html') 

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        # Get database connection
        conn = connect_auth_db()
        cursor = conn.cursor()

        # Check if email exists
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user:  # If email exists in DB
            token = generate_token()  # Generate reset token
            session['reset_token'] = token
            session['reset_email'] = email  # Store email in session

            # Send email with reset token
            msg = Message("Password Reset", sender="your_email@gmail.com", recipients=[email])
            msg.body = f"Your password reset code is: {token}"
            mail.send(msg)

            flash("Check your email for the reset code!", "info")
            return redirect(url_for('reset_password'))
        else:
            flash("No account found with this email!", "error")  # If email is not registered

        # Close connection
        cursor.close()
        conn.close()

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
            conn = connect_auth_db()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password=%s WHERE email=%s", (new_password, session['reset_email']))
            conn.commit()
            conn.close()

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
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, email, password, is_admin) VALUES (%s, %s, %s, %s)", 
                       (username, email, hashed_password, 1))
        conn.commit()
        conn.close()

        flash("New admin account created!", "success")
        return redirect(url_for('admin_dashboard'))

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

#uploading students results

@app.route('/upload', methods=['POST'])
def upload_pdf():
    if 'pdf_file' not in request.files:
        flash(f'No file selected','yellow')
        return redirect(url_for('results_page'))

    file = request.files['pdf_file']
    year = request.form.get('year')
    semester = request.form.get('semester')

    if file.filename == '' or not year or not semester:
        flash(f'Missing file, year, or semester input','yellow')
        return redirect(url_for('results_page'))

    table_name = f"{year}_{semester}_results"
    temp_pdf_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(temp_pdf_path)

    try:
        with connect_db() as conn:
            with conn.cursor() as cursor:
                # Ensure uploaded_pdfs table exists
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS uploaded_pdfs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    pdf_hash VARCHAR(64) UNIQUE
                );
                """)

                # Check if the PDF is already uploaded
                pdf_hash = generate_pdf_hash(temp_pdf_path)
                cursor.execute("SELECT pdf_hash FROM uploaded_pdfs WHERE pdf_hash = %s", (pdf_hash,))
                if cursor.fetchone():
                    flash(f"This PDF has already been uploaded. No changes made.",'warning')
                    os.remove(temp_pdf_path)
                    return redirect(url_for('results_page'))

                # Create results table dynamically if not exists
                cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS `{table_name}` (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    htno VARCHAR(20),
                    subcode VARCHAR(20),
                    subname VARCHAR(255),
                    internals INT,
                    grade VARCHAR(10),
                    credits FLOAT,
                    UNIQUE KEY unique_record (htno, subcode)
                );
                """)

                # Extract tables from PDF
                tables = tabula.read_pdf(temp_pdf_path, pages="all", multiple_tables=True, stream=True)
                os.remove(temp_pdf_path)  # Remove temp file after reading
                df = pd.concat(tables, ignore_index=True)

                # Define expected columns
                if "Sno" in df.columns:
                    df = df.drop(columns=["Sno"])
                if "sno" in df.columns:
                    df = df.drop(columns=["sno"])
                if "SNO" in df.columns:
                    df = df.drop(columns=["Sno"])

                expected_columns = ["Htno", "Subcode", "Subname", "Internals", "Grade", "Credits"]
                df = df.iloc[:, :len(expected_columns)]

                # Normalize column names to ensure consistency
                df.columns = [col.strip().capitalize() for col in df.columns]

                #df.columns = df.columns.str.upper()
                #df.columns = df.columns.str.capitalize()


                df = df.dropna()
                df = df[df["Htno"] != "Htno"]

                def clean_data(value):
                    """Helper function to handle non-numeric values."""
                    if isinstance(value, str) and value.strip() in ('---', '', 'N/A'):
                        return 0
                    try:
                        return int(value)
                    except ValueError:
                        return 0
                def clean_data1(value):
                    """Helper function to handle non-numeric values."""
                    if isinstance(value, str) and value.strip() in ('---', '', 'N/A'):
                        return 0
                    try:
                        return float(value)
                    except ValueError:
                        return 0

                df["Internals"] = df["Internals"].apply(clean_data)
                df["Credits"] = df["Credits"].apply(clean_data1)
                #df["Credits"] = float(df["Credits"])
                #df["Credits"] = df["Credits"].apply(lambda x: float(x) if isinstance(x, (int, float)) else 0)


                # Insert or update records
                for _, row in df.iterrows():
                    htno = row["Htno"]
                    subcode = row["Subcode"]
                    subname = row["Subname"]
                    internals = int(row["Internals"])
                    grade = row["Grade"]
                    credits = float( row["Credits"])

                    cursor.execute(f"SELECT grade, credits FROM `{table_name}` WHERE htno = %s AND subcode = %s", (htno, subcode))
                    existing_record = cursor.fetchone()

                    if existing_record:
                        existing_grade, existing_credits = existing_record
                        if (existing_grade != grade and grade.upper() !="NO CHANGE" and grade.upper() !="ABSENT" ):
                            if (existing_grade.upper()=="NO CHANGE" or existing_grade.upper()=="ABSENT" or ord(existing_grade) > ord(grade)):
                                cursor.execute(f"""
                                UPDATE `{table_name}` SET grade = %s , credits = %s WHERE htno = %s AND subcode = %s
                                """, (grade, credits, htno, subcode))
                    else:
                        cursor.execute(f"""
                        INSERT INTO `{table_name}` (htno, subcode, subname, internals, grade, credits)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """, (htno, subcode, subname, internals, grade, credits))

                # Save the new PDF hash
                cursor.execute("INSERT INTO uploaded_pdfs (pdf_hash) VALUES (%s)", (pdf_hash,))
                conn.commit()

        flash(f'PDF data uploaded successfully!','success')
    except Exception as e:
        flash(f'Error processing PDF: {str(e)}','danger')

    return redirect(url_for('results_page'))

# searching student results using roll number
@app.route('/get_results', methods=['POST'])
def get_results():
    htnumber = request.form.get('htno')
    if len(htnumber) !=10  :
        flash(f'invalid roll number','warning')
        return redirect(url_for('search_page'))
    semester_tables = ["1_1_results", "1_2_results", "2_1_results", "2_2_results", 
                       "3_1_results", "3_2_results", "4_1_results", "4_2_results"]

    student_results = {}
    sgpa_results = {}
    total_cgpa_points = 0
    total_cgpa_credits = 0

    grade_values = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP":0 , "ABSENT":0, "COMPLE": 0}

    try:
        with connect_db() as conn:
            with conn.cursor() as cursor:
                # Fetch student name
                cursor.execute("SELECT name FROM students WHERE roll_number = %s LIMIT 1", (htnumber,))
                global student_name 
                student_name = cursor.fetchone()
                student_name = student_name[0] if student_name else "Unknown"
                

                for table in semester_tables:
                    try:
                        cursor.execute(f"SELECT subname, grade, credits FROM `{table}` WHERE htno = %s", (htnumber,))
                        results = cursor.fetchall()
                        student_results[table] = results if results else "No Data"

                        if results:
                            total_credits = 0
                            total_grade_points = 0

                            for subname, grade, credits in results:
                                if grade in ("F", "MP", "ABSENT") or credits == 0.0:
                                    try:
                                        # Fetch credits from passed students
                                        cursor.execute(
                                            f"SELECT credits FROM `{table}` WHERE subname = %s AND grade NOT IN ('F', 'MP', 'ABSENT') LIMIT 1",
                                            (subname,)
                                        )
                                        fetched_credit = cursor.fetchone()
                                        if fetched_credit and fetched_credit[0] is not None:
                                            credits = fetched_credit[0]
                                    except pymysql.MySQLError as fetch_error:
                                        print(f"Error fetching credits for {subname}: {fetch_error}")
                                        credits = 0  # Default to 0 if fetching fails

                                grade_point = grade_values.get(grade, 0)
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

                    except pymysql.MySQLError as table_error:
                        print(f"Error processing table {table}: {table_error}")
                        student_results[table] = "No Data"
                        sgpa_results[table] = "No Data"

                cgpa = round(total_cgpa_points / total_cgpa_credits, 2) if total_cgpa_credits > 0 else "No CGPA"
            
    except pymysql.MySQLError as e:
        flash(f"Error fetching results. Please try again.{str(e)}",'danger')
        return redirect(url_for('search_page'))
        #render_template('search.htmml')

    return render_template('results.html', student_name=student_name, student_results=student_results, sgpa_results=sgpa_results, cgpa=cgpa, htnumber=htnumber)

# fetching all student results 

@app.route('/all_students')
def all_students():
    global section_results
    semester_tables = [
        "1_1_results", "1_2_results", "2_1_results", "2_2_results",
        "3_1_results", "3_2_results", "4_1_results", "4_2_results"
    ]

    grade_values = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "COMPLE": 0}
    section_results = {}

    try:
        # Connect to student database
        student_conn = connect_student_db()
        student_cursor = student_conn.cursor(pymysql.cursors.DictCursor)

        # Get all section tables
        student_cursor.execute("SHOW TABLES")
        section_tables = [table["Tables_in_student_db"] for table in student_cursor.fetchall()]

        for section in section_tables:
            student_cursor.execute(f"SELECT roll_number, name FROM `{section}`")
            students = student_cursor.fetchall()

            section_cgpa_data = []

            for student in students:
                roll_number = student["roll_number"]
                name = student["name"]

                if "HP" not in roll_number:
                    continue  # Skip students without "HP" in roll number

                total_cgpa_points = 0
                total_cgpa_credits = 0

                try:
                    # Connect to the results database
                    result_conn = connect_result_db()
                    result_cursor = result_conn.cursor(pymysql.cursors.DictCursor)

                    for table in semester_tables:
                        try:
                            # Fetch grade and credits
                            result_cursor.execute(
                                f"SELECT subname, grade, credits FROM `{table}` WHERE htno = %s", (roll_number,)
                            )
                            results = result_cursor.fetchall()

                            if results:
                                total_credits = 0
                                total_grade_points = 0

                                for row in results:
                                    subname = row["subname"]
                                    grade = row["grade"]
                                    credits = row["credits"]

                                    # Handle failed grades (F, MP, ABSENT) by fetching alternative credits
                                    if grade in ("F", "MP", "ABSENT") or credits == 0.0:
                                        try:
                                            result_cursor.execute(
                                                f"SELECT credits FROM `{table}` WHERE subname = %s AND grade NOT IN ('F', 'MP', 'ABSENT') LIMIT 1",
                                                (subname,)
                                            )
                                            fetched_credit = result_cursor.fetchone()
                                            if fetched_credit and fetched_credit["credits"] is not None:
                                                credits = fetched_credit["credits"]
                                        except pymysql.MySQLError as fetch_error:
                                            print(f"Error fetching credits for {subname}: {fetch_error}")
                                            credits = 0  # Default to 0 if fetching fails

                                    # Compute grade points
                                    grade_point = grade_values.get(grade, 0)
                                    total_credits += credits
                                    total_grade_points += grade_point * credits

                                # Accumulate CGPA calculation
                                if total_credits > 0:
                                    total_cgpa_points += total_grade_points
                                    total_cgpa_credits += total_credits

                        except pymysql.MySQLError:
                            print(f"Skipping missing table {table}")

                    # Close the results database connection
                    result_conn.close()

                except pymysql.MySQLError as e:
                    print(f"Error connecting to result database: {e}")

                # Calculate final CGPA
                cgpa = round(total_cgpa_points / total_cgpa_credits, 2) if total_cgpa_credits > 0 else "No CGPA"

                section_cgpa_data.append({
                    "roll_number": roll_number,
                    "name": name,
                    "cgpa": cgpa
                })

            section_results[section] = section_cgpa_data

        # Close the student database connection
        student_conn.close()

    except Exception as e:
        flash(f"Error fetching student CGPAs: {str(e)}")
        return redirect(url_for('home'))

    return render_template('all_students.html', section_results=section_results)

#download option for individual section results
@app.route('/download_section_excel/<section>')
def download_section_excel(section):
    """Generate and download an Excel file for a specific section."""
    if section not in section_results:
        flash("Section data not found!")
        return redirect(url_for('all_students'))

    # Create a new workbook and sheet
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = f"{section}_CGPA"

    # Add headers
    ws.append(["Roll Number", "Name", "CGPA"])

    # Add student data
    for student in section_results[section]:
        ws.append([student['roll_number'], student['name'], student['cgpa']])

    # Save to a BytesIO buffer
    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    return Response(buffer, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f"attachment; filename={section}_cgpa.xlsx"})


#download option for all section results
@app.route('/download_all_sections_excel')
def download_all_sections_excel():
    """Generate and download an Excel file for all sections."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "All_Sections_CGPA"

    # Add headers
    ws.append(["Section", "Roll Number", "Name", "CGPA"])

    # Add student data for all sections
    for section, students in section_results.items():
        for student in students:
            ws.append([section, student['roll_number'], student['name'], student['cgpa']])

    # Save to a BytesIO buffer
    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    return Response(buffer, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": "attachment; filename=all_sections_cgpa.xlsx"})

#storing section wise student name  in  "student_db" 
def process_excel(file_path):
    conn = connect_student_db()
    if not conn:
        return
    
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
            
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS `{table_name}` (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255),
                    roll_number VARCHAR(50) UNIQUE
                )
            """)
            
            for _, row in df.iterrows():
                name = str(row['name']).strip() if pd.notna(row['name']) else ""
                roll_number = str(row['roll_number']).strip() if pd.notna(row['roll_number']) else ""
                
                if not name or not roll_number:
                    continue
                
                cursor.execute(f"INSERT IGNORE INTO `{table_name}` (name, roll_number) VALUES (%s, %s)", 
                               (name, roll_number))
            
            processed_data[table_name] = df.to_dict(orient='records')
    
    conn.commit()
    cursor.close()
    conn.close()
    return {"message1": "students data for sections uploaded"}

#storing student names in "college_results" into single tabel
def process_excel_to_single_table(file_path):
    conn = connect_result_db()
    if not conn:
        return
    
    cursor = conn.cursor()
    xls = pd.ExcelFile(file_path)
    roll_number_pattern = re.compile(r"^\d{2}[A-Z]{2}\d{1,2}[A-Z0-9]+$", re.IGNORECASE)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255),
            roll_number VARCHAR(50) UNIQUE
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
                
                cursor.execute("""
                    INSERT IGNORE INTO students (name, roll_number) VALUES (%s, %s)
                """, (name, roll_number))
    
    conn.commit()
    cursor.close()
    conn.close()
    return {"message2": "students data successfully uploaded into name table "}

#function to upload student details into 2 databases
@app.route("/upload1", methods=["POST"])

def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files["file"]
    
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    
    if file:
        file_path = os.path.join(UPLOAD_FOLDER1, file.filename)
        file.save(file_path)
        response1 = process_excel(file_path)
        response2 = process_excel_to_single_table(file_path)
        msg1=response1["message1"]
        msg2=response2["message2"]
        flash(msg1,'success')
        flash(msg2,'success')
        return render_template("upload_student_details.html")# message1=response1["message1"],message2=response2["message2"])


if __name__ == '__main__':
    app.run(debug=True)

