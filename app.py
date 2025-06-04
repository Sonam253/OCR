from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
import os
import pytesseract
from PIL import Image
from werkzeug.utils import secure_filename
import datetime
import smtplib
import random
import string
import time
from email.mime.text import MIMEText

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.secret_key = 'supersecretkey'  # For session management
USERS_FILE = 'users.txt'
HISTORY_FILE = 'history.txt'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

# Persistent user store (username: {password, email})
users = {}

# SMTP config (fill in your details)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_EMAIL = 'your_email@gmail.com'  # <-- CHANGE THIS
SMTP_PASSWORD = 'your_app_password'  # <-- CHANGE THIS

# Store codes in memory: {email: (code, expiry_time)}
reset_codes = {}

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) == 3:
                    username, password, email = parts
                    users[username] = {'password': password, 'email': email}
                elif len(parts) == 2:
                    username, password = parts
                    users[username] = {'password': password, 'email': ''}

def save_user(username, password, email):
    with open(USERS_FILE, 'a') as f:
        f.write(f'{username}:{password}:{email}\n')

def update_user(username, password=None, email=None):
    if username in users:
        if password:
            users[username]['password'] = password
        if email is not None:
            users[username]['email'] = email
        # Rewrite all users
        with open(USERS_FILE, 'w') as f:
            for u, data in users.items():
                f.write(f"{u}:{data['password']}:{data['email']}\n")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_history(username, filename, status):
    with open(HISTORY_FILE, 'a') as f:
        f.write(f'{username},{filename},{datetime.datetime.now().isoformat()},{status}\n')

def get_history(username):
    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 4 and parts[0] == username:
                    history.append({'filename': parts[1], 'timestamp': parts[2], 'status': parts[3]})
    return history[::-1]

load_users()

@app.before_request
def require_login():
    allowed_routes = ['login', 'signup', 'static', 'reset']
    if 'logged_in' not in session and request.endpoint not in allowed_routes:
        return redirect(url_for('login'))

@app.context_processor
def inject_logged_in():
    return dict(logged_in=session.get('logged_in', False), username=session.get('username'), email=session.get('email'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        email = request.form.get('email')
        if not username or not password or not confirm or not email:
            flash('Please fill in all fields.', 'danger')
        elif username in users:
            flash('Username already exists. Please choose another.', 'danger')
        elif len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
        elif password != confirm:
            flash('Passwords do not match.', 'danger')
        else:
            users[username] = {'password': password, 'email': email}
            save_user(username, password, email)
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username]['password'] == password:
            session['logged_in'] = True
            session['username'] = username
            session['email'] = users[username]['email']
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('email', None)
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = users.get(session['username'])
    if request.method == 'POST':
        new_email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        if new_email and new_email != user['email']:
            update_user(session['username'], email=new_email)
            session['email'] = new_email
            flash('Email updated.', 'success')
        if new_password:
            if len(new_password) < 6:
                flash('New password must be at least 6 characters.', 'danger')
            elif new_password != confirm_new_password:
                flash('New passwords do not match.', 'danger')
            elif current_password != user['password']:
                flash('Current password is incorrect.', 'danger')
            else:
                update_user(session['username'], password=new_password)
                flash('Password updated.', 'success')
    user = users.get(session['username'])
    return render_template('profile.html', user=user, history=get_history(session['username']))

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form.get('email')
        username = None
        for u, data in users.items():
            if data['email'] == email:
                username = u
                break
        if not username:
            flash('No account found with that email.', 'danger')
        else:
            code = ''.join(random.choices(string.digits, k=6))
            expiry = time.time() + 600  # 10 minutes
            reset_codes[email] = (code, expiry, username)
            # Send email
            try:
                msg = MIMEText(f'Your password reset code is: {code}')
                msg['Subject'] = 'Your Password Reset Code'
                msg['From'] = SMTP_EMAIL
                msg['To'] = email
                with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                    server.starttls()
                    server.login(SMTP_EMAIL, SMTP_PASSWORD)
                    server.send_message(msg)
                flash('A verification code has been sent to your email.', 'success')
                return redirect(url_for('verify_code', email=email))
            except Exception as e:
                flash('Failed to send email: ' + str(e), 'danger')
    return render_template('forgot.html')

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    email = request.args.get('email') or request.form.get('email')
    if not email:
        flash('No email provided.', 'danger')
        return redirect(url_for('forgot'))
    if request.method == 'POST':
        code = request.form.get('code')
        new_password = request.form.get('new_password')
        confirm = request.form.get('confirm_new_password')
        entry = reset_codes.get(email)
        if not entry:
            flash('No reset request found for this email.', 'danger')
        else:
            real_code, expiry, username = entry
            if time.time() > expiry:
                flash('Verification code expired. Please request again.', 'danger')
                reset_codes.pop(email, None)
            elif code != real_code:
                flash('Invalid verification code.', 'danger')
            elif len(new_password) < 6:
                flash('Password must be at least 6 characters.', 'danger')
            elif new_password != confirm:
                flash('Passwords do not match.', 'danger')
            else:
                update_user(username, password=new_password)
                reset_codes.pop(email, None)
                flash('Password reset successful! Please log in.', 'success')
                return redirect(url_for('login'))
    return render_template('verify_code.html', email=email)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            # OCR logic
            try:
                text = ''
                if filename.lower().endswith(('png', 'jpg', 'jpeg')):
                    text = pytesseract.image_to_string(Image.open(filepath))
                elif filename.lower().endswith('pdf'):
                    from pdf2image import convert_from_path
                    images = convert_from_path(filepath)
                    for img in images:
                        text += pytesseract.image_to_string(img) + '\n'
                status = 'Verified' if text.strip() else 'Not Verified'
                save_history(session['username'], filename, status)
                session['ocr_text'] = text
                session['ocr_filename'] = filename
                session['ocr_status'] = status
                return redirect(url_for('result'))
            except Exception as e:
                flash('OCR failed: ' + str(e), 'danger')
        else:
            flash('Invalid file type.', 'danger')
    return render_template('upload.html')

@app.route('/result')
def result():
    text = session.get('ocr_text', '[No OCR result]')
    filename = session.get('ocr_filename', '[No file]')
    status = session.get('ocr_status', 'Not Verified')
    return render_template('result.html', text=text, filename=filename, status=status)

@app.route('/history')
def history():
    user_history = get_history(session['username'])
    return render_template('history.html', history=user_history)

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/api/user_history')
def api_user_history():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify(get_history(session['username']))

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True) 