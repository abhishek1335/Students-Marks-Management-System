CREATE DATABASE IF NOT EXISTS college_results;
CREATE DATABASE IF NOT EXISTS student_db;
CREATE DATABASE IF NOT EXISTS auth_db;

-- Create the user if not exists
CREATE USER IF NOT EXISTS 'flaskuser'@'%' IDENTIFIED WITH mysql_native_password BY 'flaskpass';

-- Grant privileges to flaskuser
GRANT ALL PRIVILEGES ON college_results.* TO 'flaskuser'@'%';
GRANT ALL PRIVILEGES ON student_db.* TO 'flaskuser'@'%';
GRANT ALL PRIVILEGES ON auth_db.* TO 'flaskuser'@'%';

FLUSH PRIVILEGES;

USE auth_db;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    reset_token VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO users (username, email, password, is_admin)
VALUES ('admin', 'admin@gmail.com', '$2b$12$2ky8kSXg8S1SDm06EVxEc.0wu0QNeAYhtJvSvA67p9Q5wpBD4fA0O', TRUE);
