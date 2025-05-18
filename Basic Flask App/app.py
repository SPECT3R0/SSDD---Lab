from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
import sqlite3
import os
import re
from datetime import timedelta
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

csrf = CSRFProtect(app)

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        )
        ''')
        conn.commit()

def validate_input(username, password, email):
    if not re.match("^[a-zA-Z0-9_]{3,20}$", username):
        return False, "Username must be 3-20 characters and contain only letters, numbers, and underscores"
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    try:
        validate_email(email)
        return True, ""
    except EmailNotValidError:
        return False, "Invalid email format"

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        is_valid, error_message = validate_input(username, password, email)
        if not is_valid:
            flash(error_message, 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                    (username, hashed_password, email)
                )
                conn.commit()
            flash("Registration successful! Please login.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or email already exists")
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with get_db() as conn:
            cursor = conn.cursor()
            query = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)"
            cursor.execute(query, (username, password, email))
        
        if user and check_password_hash(user['password'], password):
            app.config['SESSION_PERMANENT'] = False
            app.permanent_session_lifetime = timedelta(minutes=15)
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
    
    return render_template('dashboard.html', username=username, email=user['email'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

# Initialize the database before first request
@app.before_first_request
def initialize_database():
    init_db()

if __name__ == '__main__':
    init_db()  # Initialize database when starting the app
    app.run(debug=False)




    