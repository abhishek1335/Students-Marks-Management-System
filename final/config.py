import os
import pymysql
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def connect_db():
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', 'db'),
        user=os.getenv('MYSQL_USER', 'flaskuser'),
        password=os.getenv('MYSQL_PASSWORD', 'flaskpass'),
        database=os.getenv('RESULT_DATABASE', 'college_results'),
       
    )

def connect_student_db():
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', 'db'),
        user=os.getenv('MYSQL_USER', 'flaskuser'),
        password=os.getenv('MYSQL_PASSWORD', 'flaskpass'),
        database=os.getenv('STUDENT_DATABASE', 'student_db'),
        cursorclass=pymysql.cursors.DictCursor
    )

def connect_result_db():
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', 'db'),
        user=os.getenv('MYSQL_USER', 'flaskuser'),
        password=os.getenv('MYSQL_PASSWORD', 'flaskpass'),
        database=os.getenv('RESULT_DATABASE', 'college_results'),
        cursorclass=pymysql.cursors.DictCursor
    )

def connect_auth_db():
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', 'db'),
        user=os.getenv('MYSQL_USER', 'flaskuser'),
        password=os.getenv('MYSQL_PASSWORD', 'flaskpass'),
        database=os.getenv('AUTH_DATABASE', 'college_results'),
        cursorclass=pymysql.cursors.DictCursor
    )
