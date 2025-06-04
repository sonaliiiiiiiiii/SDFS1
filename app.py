import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from core.uploader import add_file
from core.retriever import get_file
from core.crypto_utils import load_private_key, load_public_key

app = Flask(__name__)
app.secret_key = 'your_secret_key'

USERS_FILE = 'users.json'
LOGS_FILE = 'logs.json'
DHT_FILE = 'dht.json'

# Ensure base files exist
for file_path, default_content in [
    (USERS_FILE, {}),
    (LOGS_FILE, []),
    (DHT_FILE, {})
]:
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        with open(file_path, 'w') as f:
            json.dump(default_content, f, indent=4)

def load_users():
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def load_logs():
    try:
        with open(LOGS_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def save_logs(logs):
    with open(LOGS_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

def load_dht():
    try:
        with open(DHT_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            users = load_users()
            user = users.get(session.get('user_email'))
            if user and user.get('role') == role:
                return f(*args, **kwargs)
            flash("Access denied.")
            return redirect(url_for('dashboard'))
        return wrapper
    return decorator

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/manage-users')
@login_required
@role_required('admin')
def manage_users():
    users = load_users()
    return render_template('manage_users.html', users=users)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        users = load_users()

        if email in users:
            flash('User already exists.')
            return redirect(url_for('register'))

        users[email] = {
            'password': generate_password_hash(password),
            'role': 'user'  # 👈 all users default to "user"
        }
        save_users(users)
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html', title="Register")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        users = load_users()
        user = users.get(email)

        if user and check_password_hash(user['password'], password):
            session['user_email'] = email
            session['user_role'] = user['role']
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
    return render_template('login.html', title="Login")

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_email = session['user_email']
    user_files_path = os.path.join("user_uploads", f"{user_email}.json")
    files = []

    if os.path.exists(user_files_path):
        with open(user_files_path, 'r') as f:
            files = json.load(f)

    return render_template('dashboard.html', files=files, title="Dashboard")

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if not file:
        flash('No file selected.')
        return redirect(url_for('dashboard'))

    filename = file.filename
    filepath = os.path.join("temp", filename)
    os.makedirs("temp", exist_ok=True)
    file.save(filepath)

    public_key = load_public_key("public_key.pem")
    manifest_hash = add_file(filepath, public_key)

    # Save upload history
    user_email = session['user_email']
    user_files_path = os.path.join("user_uploads", f"{user_email}.json")
    os.makedirs("user_uploads", exist_ok=True)

    if os.path.exists(user_files_path):
        with open(user_files_path, 'r') as f:
            user_files = json.load(f)
    else:
        user_files = []

    user_files.append({
        "filename": filename,
        "manifest_hash": manifest_hash,
        "timestamp": datetime.now().isoformat()
    })

    with open(user_files_path, 'w') as f:
        json.dump(user_files, f, indent=4)

    logs = load_logs()
    logs.append({
        "user": user_email,
        "action": "upload",
        "file": filename,
        "manifest_hash": manifest_hash,
        "timestamp": datetime.now().isoformat()
    })
    save_logs(logs)

    flash(f'File uploaded. Manifest hash: {manifest_hash}')
    return redirect(url_for('dashboard'))

@app.route('/retrieve', methods=['POST'])
@login_required
def retrieve():
    manifest_hash = request.form.get('manifest_hash')
    try:
        manifest_path = os.path.join("manifests", f"{manifest_hash}.json")
        with open(manifest_path, 'r') as m:
            manifest = json.load(m)

        original_name = manifest.get("filename", f"{manifest_hash[:8]}.bin")
        ext = os.path.splitext(original_name)[1]
        output_filename = f"recovered_{manifest_hash[:8]}{ext}"
        output_path = os.path.join("temp", output_filename)
        os.makedirs("temp", exist_ok=True)

        private_key = load_private_key("private_key.pem")
        get_file(manifest_hash, private_key, output_path)

        logs = load_logs()
        logs.append({
            "user": session['user_email'],
            "action": "download",
            "file": output_filename,
            "manifest_hash": manifest_hash,
            "timestamp": datetime.now().isoformat()
        })
        save_logs(logs)

        return redirect(url_for('view_file', filename=output_filename))

    except Exception as e:
        flash(f"Retrieval failed: {e}")
        return redirect(url_for('dashboard'))

@app.route('/admin')
@login_required
@role_required('admin')
def admin():
    logs = load_logs()
    dht = load_dht()
    return render_template('admin.html', logs=logs, dht=dht, title="Admin")

@app.route('/view/<filename>')
@login_required
def view_file(filename):
    return render_template('view_file.html', filename=filename)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    try:
        return send_from_directory("temp", filename, as_attachment=True)
    except Exception as e:
        flash(f"Could not download file: {e}")
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
