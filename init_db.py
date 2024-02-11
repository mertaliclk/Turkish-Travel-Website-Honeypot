import sqlite3
import hashlib

# Function to hash passwords
def hash_password(password):
    """Hash a password for storing."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Connect to the SQLite database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Create the 'users' table if it does not exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, 
    email TEXT UNIQUE, 
    password TEXT
)
''')

# Create the 'admins' table if it does not exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY, 
    email TEXT UNIQUE, 
    password TEXT
)
''')

# Create the 'comments' table if it does not exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    news_id TEXT NOT NULL,
    email TEXT NOT NULL,
    comment_text TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email) REFERENCES users(email)
)
''')

# Add users if not already present
users = [
    ('bert@example.com', '12345678'),
    ('bsc@mail.edu', '12345678'),
    ('asd@mail.com','12345678'),
    ('oz@asd.edu', '12345678')
]

for email, password in users:
    cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
    if cursor.fetchone() is None:
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))

# Add admins if not already present
admins = [
    ('asd@example.com', '12345678'),
    ('aha@mail.com', '12345678')
]

for email, password in admins:
    cursor.execute("SELECT email FROM admins WHERE email = ?", (email,))
    if cursor.fetchone() is None:
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO admins (email, password) VALUES (?, ?)", (email, hashed_password))

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Database initialized, admin, users, and comments table added successfully.")
