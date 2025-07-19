# tasks.py
import os
import re
import gc
import pandas as pd
import sqlite3
import tabula
import hashlib

# Import database connection functions from your config.py
# The worker process needs to know how to connect to the DBs too.
from config import connect_results_db, RESULTS_DB_PATH
# PDF Hashing Function (can be shared or defined here)
# It's good to keep it consistent with app.py if it's used there too.
def generate_pdf_hash(file_path):
    """Generates a SHA256 hash of the PDF file content."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

# The actual PDF processing function that will be run by RQ
def process_pdf_task(temp_pdf_path, year, semester, table_name, main_db_path):
    """
    Processes the uploaded PDF, extracts data, and stores it in the database.
    This function runs in a background worker process.
    """
    print(f"--- Starting background processing for: {temp_pdf_path} (Year: {year}, Semester: {semester}, Table: {table_name}) ---")

    try:
        # Establish connection to the main results database within the task
        # Use the passed main_db_path to ensure the correct database is targeted
        conn = sqlite3.connect(main_db_path)
        conn.row_factory = sqlite3.Row
        
        with conn:
            cursor = conn.cursor()

            # Ensure uploaded_pdfs table exists
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS uploaded_pdfs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pdf_hash TEXT UNIQUE
            );
            """)

            # Check if the PDF is already uploaded (re-check in worker to be safe)
            pdf_hash = generate_pdf_hash(temp_pdf_path)
            cursor.execute("SELECT pdf_hash FROM uploaded_pdfs WHERE pdf_hash = ?", (pdf_hash,))
            if cursor.fetchone():
                print(f"PDF {os.path.basename(temp_pdf_path)} already uploaded (hash: {pdf_hash}). Skipping processing.")
                os.remove(temp_pdf_path) # Clean up the temporary file
                return {"status": "skipped", "message": "PDF already uploaded, no changes made."}

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
            tables = tabula.read_pdf(temp_pdf_path, pages="all", multiple_tables=True, stream=True)
            print(f"Tabula extraction complete. Found {len(tables)} tables.")
            
            # Explicitly remove temporary PDF file as soon as it's read by the worker
            os.remove(temp_pdf_path)
            print(f"Removed temporary PDF file: {temp_pdf_path}")
            gc.collect() # Trigger garbage collection

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
                
                current_columns = [col for col in table_df.columns if col in expected_columns_template]
                df_filtered = table_df[current_columns].copy()

                for col in expected_columns_template:
                    if col not in df_filtered.columns:
                        df_filtered[col] = None
                df_filtered = df_filtered[expected_columns_template]

                df_filtered = df_filtered.dropna(subset=["Htno", "Subcode"])
                df_filtered = df_filtered[df_filtered["Htno"].astype(str).str.lower() != "htno"]

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
                
                del table_df
                del df_filtered
                gc.collect()

            grade_rank = {"A+": 10, "A": 9, "B": 8, "C": 7, "D": 6, "E": 5, "F": 0, "MP": 0, "ABSENT": 0, "NO CHANGE": -1}

            insert_count = 0
            update_count = 0

            for row_tuple in all_data:
                htno, subcode, subname, internals, grade, credits = row_tuple
                
                htno = str(htno).strip()
                subcode = str(subcode).strip()
                subname = str(subname).strip()
                grade = str(grade).strip()

                cursor.execute(f"SELECT grade, credits FROM `{table_name}` WHERE htno = ? AND subcode = ?", (htno, subcode))
                existing_record = cursor.fetchone()

                if existing_record:
                    existing_grade, existing_credits = existing_record
                    new_grade_rank = grade_rank.get(grade.upper(), -1)
                    old_grade_rank = grade_rank.get(existing_grade.upper(), -1)

                    should_update = False
                    if new_grade_rank > old_grade_rank:
                        should_update = True
                    elif old_grade_rank <= 0 and new_grade_rank > 0:
                        should_update = True
                    elif new_grade_rank == old_grade_rank and credits != existing_credits:
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
            
            cursor.execute("INSERT INTO uploaded_pdfs (pdf_hash) VALUES (?)", (pdf_hash,))
            conn.commit()
            print(f"Database commit successful. Inserted: {insert_count}, Updated: {update_count}")
            print(f"--- Background processing complete for: {os.path.basename(temp_pdf_path)}. Inserted: {insert_count}, Updated: {update_count} ---")
            
            return {"status": "success", "inserted": insert_count, "updated": update_count}

    except Exception as e:
        print(f"!!! ERROR during background PDF processing for {os.path.basename(temp_pdf_path)}: {e}")
        import traceback
        traceback.print_exc()
        # Even on error, attempt to remove the temp file if it still exists
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)
        # Raise the exception so RQ marks the job as failed and stores the traceback
        raise # Important for error visibility in RQ dashboard / logs
