import psycopg2

# Hardcoded secrets — BAD
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "admin123"
API_TOKEN = "sk-live-abc123xyz456"

def get_user(user_id):
    # SQL Injection — BAD
    conn = psycopg2.connect(password=DB_PASSWORD)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def render_profile(username):
    # XSS vulnerability — BAD
    return f"<div class='profile'>Welcome {username}</div>"

def run_command(user_input):
    # Command injection — BAD
    import os
    os.system("echo " + user_input)
