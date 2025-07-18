# worker.py
import os
import pandas as pd
from celery import Celery
import redis
import hashlib
import json
import logging
import sqlite3
import tabula # Import tabula for PDF processing

# Import database connection functions and path from config.py
from config import (
    connect_results_db,
    connect_student_db,
    initialize_all_dbs,
    DATABASE_DIR, # Import DATABASE_DIR for file paths
    RESULTS_DB_PATH, # Specific path for results.db
    STUDENT_DB_PATH # Specific path for student.db
)

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Celery Configuration ---
# Use an environment variable for Redis URL (important for Render)
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6377/0')

celery_app = Celery('my_worker', broker=REDIS_URL, backend=REDIS_URL)

# Configure Celery to include task modules (if you break tasks into separate files later)
# celery_app.conf.update(
#     include=['worker'], # If this file contains the tasks
# )

# --- Directory for uploaded files ---
# Ensure UPLOAD_FOLDER uses DATABASE_DIR for persistence
UPLOAD_FOLDER = os.path.join(DATABASE_DIR, 'uploads')
# Fix: Using exist_ok=True ensures the directory is created if it doesn't exist,
# and no error is raised if it already exists, preventing race conditions.
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
logger.info(f"Ensured upload folder exists: {UPLOAD_FOLDER}")

# --- Helper function for hashing file content ---
def hash_file(filepath):
    """Generates a SHA256 hash of a file's content."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)  # Read in 8KB chunks
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

# --- Excel Processing Logic ---
@celery_app.task(bind=True, max_retries=3, default_retry_delay=300) # Retry after 5 minutes
def process_excel_task(self, file_path, year, exam_type, course, semester):
    """
    Celery task to process an Excel file, extract student and result data,
    and store it in respective SQLite databases.
    """
    logger.info(f"Starting Excel processing for file: {file_path}")
    results_conn = None
    student_conn = None

    try:
        # Check if the file has already been processed based on its hash
        file_hash = hash_file(file_path)
        results_conn = connect_results_db()
        cursor = results_conn.cursor()
        cursor.execute("SELECT id FROM uploaded_pdfs WHERE pdf_hash = ?", (file_hash,))
        if cursor.fetchone():
            logger.warning(f"File {file_path} (hash: {file_hash}) already processed. Skipping.")
            return {"status": "skipped", "message": "File already processed."}
        
        # Read Excel data
        try:
            df = pd.read_excel(file_path)
            logger.info(f"Successfully read Excel file: {file_path}")
        except Exception as e:
            logger.error(f"Error reading Excel file {file_path}: {e}")
            raise  # Re-raise to trigger retry or error handling

        # Sanitize column names for SQLite table names and column names
        df.columns = [col.strip().replace(' ', '_').replace('.', '').replace('/', '_').replace('\\', '_').replace('-', '_').lower() for col in df.columns]

        # Define table names based on parameters
        # For student.db, a table per year_exam_course_semester for results
        student_results_table_name = f"results_{year}_{exam_type}_{course}_{semester}".lower()
        # Sanitize for SQL table name rules
        student_results_table_name = re.sub(r'[^a-zA-Z0-9_]', '', student_results_table_name)
        

        # --- Process for student.db (detailed results per student per exam) ---
        student_conn = connect_student_db()
        student_cursor = student_conn.cursor()
        student_cursor.row_factory = sqlite3.Row # Allows column access by name

        # Create table dynamically for detailed results in student.db
        columns_sql = []
        for col in df.columns:
            if col == 'roll_number':
                columns_sql.append(f"{col} TEXT UNIQUE NOT NULL")
            elif 'marks' in col or 'grade' in col or 'result' in col or 'credits' in col:
                columns_sql.append(f"{col} TEXT") # Or INTEGER/REAL if you know it's purely numeric
            else:
                columns_sql.append(f"{col} TEXT")
        
        create_table_sql = f"CREATE TABLE IF NOT EXISTS `{student_results_table_name}` (id INTEGER PRIMARY KEY AUTOINCREMENT, {', '.join(columns_sql)})"
        
        logger.info(f"Creating/Verifying table in student.db: {student_results_table_name}")
        student_cursor.execute(create_table_sql)
        student_conn.commit()

        # Insert data into the student_results_table_name table in student.db
        insert_columns = ', '.join(df.columns)
        placeholders = ', '.join(['?' for _ in df.columns])
        insert_sql = f"INSERT OR REPLACE INTO `{student_results_table_name}` ({insert_columns}) VALUES ({placeholders})"
        
        data_to_insert = [tuple(row) for row in df.values]
        
        logger.info(f"Inserting {len(data_to_insert)} rows into {student_results_table_name} in student.db...")
        try:
            student_cursor.executemany(insert_sql, data_to_insert)
            student_conn.commit()
            logger.info(f"Successfully inserted data into {student_results_table_name} in student.db.")
        except sqlite3.Error as e:
            logger.error(f"Error inserting data into {student_results_table_name}: {e}")
            student_conn.rollback() # Rollback on error
            raise # Re-raise to trigger retry/error handling


        # --- Process for results.db (general students list) ---
        # This assumes 'students' table in results.db is just for name and roll_number
        results_cursor = results_conn.cursor()

        # Update or insert into the general 'students' table in results.db
        # Assuming 'name' and 'roll_number' are present in the Excel file
        if 'name' in df.columns and 'roll_number' in df.columns:
            students_data = df[['name', 'roll_number']].drop_duplicates()
            
            # Using INSERT OR IGNORE to add new students without erroring on existing ones
            insert_student_sql = "INSERT OR IGNORE INTO students (name, roll_number) VALUES (?, ?)"
            
            students_to_insert = [tuple(row) for row in students_data.values]
            logger.info(f"Updating/Inserting {len(students_to_insert)} students into general students table in results.db...")
            try:
                results_cursor.executemany(insert_student_sql, students_to_insert)
                results_conn.commit()
                logger.info(f"Successfully updated/inserted students into general students table.")
            except sqlite3.Error as e:
                logger.error(f"Error updating/inserting students into general students table: {e}")
                results_conn.rollback()
                raise

        # Record the file hash in uploaded_pdfs table to prevent re-processing
        logger.info(f"Recording file hash {file_hash} in uploaded_pdfs.")
        try:
            cursor.execute("INSERT INTO uploaded_pdfs (pdf_hash) VALUES (?)", (file_hash,))
            results_conn.commit()
            logger.info(f"File hash recorded successfully.")
        except sqlite3.IntegrityError:
            logger.warning(f"File hash {file_hash} already exists in uploaded_pdfs table (should have been caught earlier).")
        except sqlite3.Error as e:
            logger.error(f"Error recording file hash: {e}")
            results_conn.rollback()
            raise

        # --- Clean up the uploaded file ---
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Deleted uploaded file: {file_path}")

        logger.info(f"Successfully processed Excel file: {file_path}")
        return {"status": "success", "message": "Excel file processed and data stored."}

    except Exception as e:
        logger.error(f"Error processing Excel file {file_path}: {e}", exc_info=True)
        # Attempt to retry the task
        try:
            self.retry(exc=e)
        except Exception as retry_e:
            logger.error(f"Max retries exceeded or failed to retry task: {retry_e}")
            return {"status": "failure", "message": f"Failed to process Excel file after retries: {e}"}
    finally:
        if results_conn:
            results_conn.close()
        if student_conn:
            student_conn.close()


# --- PDF Marks Processing Logic (NEW TASK) ---
@celery_app.task(bind=True, max_retries=3, default_retry_delay=300)
def process_marks_pdf_task(self, file_path, year, semester):
    """
    Celery task to process an uploaded PDF file, extract marks,
    and store them in the database.
    """
    logger.info(f"Starting PDF marks processing for file: {file_path} for Year: {year}, Semester: {semester}")
    results_conn = None
    try:
        file_hash = hash_file(file_path) # Reuse your existing hash_file helper

        results_conn = connect_results_db()
        cursor = results_conn.cursor()
        cursor.row_factory = sqlite3.Row # Allows column access by name

        # Re-check if PDF was already processed (good practice for idempotency)
        cursor.execute("SELECT id FROM uploaded_pdfs WHERE pdf_hash = ?", (file_hash,))
        if cursor.fetchone():
            logger.warning(f"PDF {file_path} (hash: {file_hash}) already processed. Skipping in worker.")
            return {"status": "skipped", "message": "PDF already processed."}

        # --- PDF Parsing Logic using tabula-py ---
        # This part is highly dependent on the structure of your PDFs.
        # You might need to adjust pages, area, columns, etc.
        try:
            # tabula.read_pdf returns a list of DataFrames, one for each table found
            # You might need to specify area or columns for better extraction
            dfs = tabula.read_pdf(
                file_path,
                pages='all',
                multiple_tables=True,
                stream=True, # Use stream=True for structured data
                guess=False  # Set to True if you want tabula to guess table areas
                # area=[top, left, bottom, right] # Example: specify area if tables are in a fixed region
                # columns=[col1, col2, ...] # Example: specify column boundaries
            )
            logger.info(f"Extracted {len(dfs)} tables from PDF: {file_path}")

            # Define the table name where marks will be stored in results.db
            # This should match your existing schema or be created dynamically
            # Assuming a general marks table in results.db for PDF data
            marks_table_name = f"y{year}_s{semester}_results_pdf".lower() # Distinct name for PDF results
            marks_table_name = re.sub(r'[^a-zA-Z0-9_]', '', marks_table_name) # Sanitize

            # Create the table if it doesn't exist (assuming columns like htno, subname, grade, credits)
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS `{marks_table_name}` (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    htno TEXT NOT NULL,
                    subname TEXT,
                    grade TEXT,
                    credits REAL,
                    UNIQUE(htno, subname) ON CONFLICT REPLACE
                )
            """)
            results_conn.commit()
            logger.info(f"Ensured table `{marks_table_name}` exists in results.db.")

            # Process each DataFrame and insert into the database
            total_rows_inserted = 0
            for df in dfs:
                if df.empty:
                    continue

                # Standardize column names for insertion (adjust based on your PDF's actual columns)
                # Example: Assuming PDF columns like 'HTNO', 'Subject', 'Grade', 'Credits'
                # You'll need to inspect your PDF's output from tabula to map these correctly.
                df.columns = [col.strip().replace(' ', '_').replace('.', '').replace('/', '_').replace('\\', '_').replace('-', '_').lower() for col in df.columns]

                # Filter for essential columns and ensure they exist
                required_cols = ['htno', 'subname', 'grade', 'credits'] # Adjust these based on your PDF and DB schema
                if not all(col in df.columns for col in required_cols):
                    logger.warning(f"Skipping a table due to missing required columns in PDF: {df.columns}. Required: {required_cols}")
                    continue

                # Prepare data for insertion
                data_to_insert = []
                for index, row in df.iterrows():
                    htno = str(row.get('htno', '')).strip()
                    subname = str(row.get('subname', '')).strip()
                    grade = str(row.get('grade', '')).strip()
                    credits = float(row.get('credits', 0.0)) # Convert to float, default to 0.0

                    if htno and subname: # Only insert if essential fields are present
                        data_to_insert.append((htno, subname, grade, credits))

                if data_to_insert:
                    insert_sql = f"INSERT OR REPLACE INTO `{marks_table_name}` (htno, subname, grade, credits) VALUES (?, ?, ?, ?)"
                    cursor.executemany(insert_sql, data_to_insert)
                    results_conn.commit()
                    total_rows_inserted += len(data_to_insert)
                    logger.info(f"Inserted {len(data_to_insert)} rows into `{marks_table_name}`.")

            logger.info(f"Total {total_rows_inserted} marks records inserted/updated from PDF: {file_path}")

            # Record the file hash in uploaded_pdfs table AFTER successful processing
            cursor.execute("INSERT INTO uploaded_pdfs (pdf_hash) VALUES (?)", (file_hash,))
            results_conn.commit()
            logger.info(f"File hash {file_hash} recorded in uploaded_pdfs after successful PDF processing.")

        except Exception as pdf_process_error:
            logger.error(f"Error during tabula PDF processing for {file_path}: {pdf_process_error}", exc_info=True)
            results_conn.rollback() # Rollback any partial inserts
            raise # Re-raise to trigger Celery retry mechanism

        # --- Clean up the uploaded file ---
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Deleted uploaded PDF file: {file_path}")

        logger.info(f"Successfully processed PDF file: {file_path}")
        return {"status": "success", "message": "PDF processed and marks stored."}

    except Exception as e:
        logger.error(f"Overall error in process_marks_pdf_task for {file_path}: {e}", exc_info=True)
        try:
            self.retry(exc=e)
        except Exception as retry_e:
            logger.error(f"Max retries exceeded or failed to retry task for PDF: {retry_e}")
            return {"status": "failure", "message": f"Failed to process PDF file after retries: {e}"}
    finally:
        if results_conn:
            results_conn.close()


# --- Example of another task (if needed) ---
@celery_app.task
def generate_pdf_task(roll_number, year, exam_type, course, semester):
    """
    Placeholder task for generating a PDF result for a specific student.
    This would query the student.db for the relevant result data.
    """
    logger.info(f"Generating PDF for Roll Number: {roll_number} for {year} {exam_type} {course} {semester}")
    student_conn = None
    try:
        student_conn = connect_student_db()
        student_conn.row_factory = sqlite3.Row # Ensure rows can be accessed by column name
        cursor = student_conn.cursor()

        # Construct table name
        table_name = f"results_{year}_{exam_type}_{course}_{semester}".lower()
        table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name) # Sanitize

        # Fetch student's results from the specific table
        cursor.execute(f"SELECT * FROM `{table_name}` WHERE roll_number = ?", (roll_number,))
        student_data = cursor.fetchone()

        if student_data:
            # Convert Row object to dictionary for easier access
            student_dict = dict(student_data)
            logger.info(f"Found student data for {roll_number}: {student_dict}")
            
            # --- PDF Generation Logic (Placeholder) ---
            # You would use a library like ReportLab or FPDF here.
            # For now, just simulate success
            pdf_output_dir = os.path.join(DATABASE_DIR, 'generated_pdfs') # Changed to use DATABASE_DIR
            os.makedirs(pdf_output_dir, exist_ok=True) 
            pdf_output_path = os.path.join(pdf_output_dir, f"result_{roll_number}_{year}_{exam_type}_{course}_{semester}.pdf")
            
            with open(pdf_output_path, "w") as f: # Create a dummy file
                f.write(f"This is a dummy PDF for {student_dict.get('name', 'N/A')} (Roll No: {roll_number}) - {year} {exam_type} {course} {semester}")

            logger.info(f"PDF generated (or simulated) for {roll_number} at {pdf_output_path}")
            return {"status": "success", "path": pdf_output_path}
        else:
            logger.warning(f"No result found for Roll Number: {roll_number} in table {table_name}")
            return {"status": "failure", "message": "No result data found."}

    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            logger.error(f"Table '{table_name}' does not exist in student.db. Did you upload the Excel for this configuration?")
            return {"status": "failure", "message": f"No results uploaded for {year} {exam_type} {course} {semester}."}
        logger.error(f"Database error for Roll Number {roll_number}: {e}", exc_info=True)
        return {"status": "failure", "message": f"Database error: {e}"}
    except Exception as e:
        logger.error(f"Error generating PDF for Roll Number {roll_number}: {e}", exc_info=True)
        return {"status": "failure", "message": f"Failed to generate PDF: {e}"}
    finally:
        if student_conn:
            student_conn.close()


# This block ensures that Celery app is run correctly when the worker starts
if __name__ == '__main__':
    # Initialize all databases when the worker starts.
    # This ensures tables are created before tasks try to access them.
    # This is safe to call multiple times as CREATE TABLE IF NOT EXISTS handles existing tables.
    logger.info("Worker starting up. Initializing databases...")
    initialize_all_dbs()
    logger.info("Databases initialized.")
    celery_app.worker_main(['worker', '--loglevel=info'])
