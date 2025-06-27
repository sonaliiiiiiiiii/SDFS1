import os, json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from core.uploader import add_file
from core.retriever import get_file
from core.crypto_utils import load_private_key, load_public_key
from dotenv import load_dotenv

load_dotenv()  # Load environment variables

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Ensure required files
for fn, default in [('users.json', {}), ('logs.json', []), ('dht.json', {})]:
    if not os.path.exists(fn):
        with open(fn, 'w') as f:
            json.dump(default, f, indent=4)

# ---------------- Utility Functions ----------------

def load_users():
    return json.load(open('users.json')) if os.path.exists('users.json') else {}

def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f, indent=4)

def load_logs():
    return json.load(open('logs.json')) if os.path.exists('logs.json') else []

def save_logs(logs):
    with open('logs.json', 'w') as f:
        json.dump(logs, f, indent=4)

def load_dht():
    return json.load(open('dht.json')) if os.path.exists('dht.json') else {}

# ---------------- Decorators ----------------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_email' not in session:
            flash("Login required.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = load_users().get(session.get('user_email'))
            if user and user.get('role') == role:
                return f(*args, **kwargs)
            flash("Access denied.")
            return redirect(url_for('dashboard'))
        return wrapper
    return decorator

# ---------------- Routes ----------------

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        pwd = request.form['password']
        users = load_users()
        if email in users:
            flash('User already exists.')
            return redirect(url_for('register'))

        users[email] = {
            'password': generate_password_hash(pwd),
            'role': 'user'
        }
        save_users(users)
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        pwd = request.form['password']
        users = load_users()
        user = users.get(email)

        if user and check_password_hash(user['password'], pwd):
            session['user_email'] = email
            session['user_role'] = user['role']
            flash('Login successful.')
            return redirect(url_for('dashboard'))
        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    path = f"user_uploads/{session['user_email']}.json"
    files = json.load(open(path)) if os.path.exists(path) else []
    return render_template('dashboard.html', files=files)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if not file:
        flash("No file selected.")
        return redirect(url_for('dashboard'))

    os.makedirs("temp", exist_ok=True)
    filepath = os.path.join("temp", file.filename)
    file.save(filepath)
    manifest_hash = add_file(filepath, load_public_key("public_key.pem"))

    uploads_path = f"user_uploads/{session['user_email']}.json"
    uploads = json.load(open(uploads_path)) if os.path.exists(uploads_path) else []
    uploads.append({
        "filename": file.filename,
        "manifest_hash": manifest_hash,
        "timestamp": datetime.now().isoformat()
    })
    os.makedirs("user_uploads", exist_ok=True)
    json.dump(uploads, open(uploads_path, 'w'), indent=4)

    logs = load_logs()
    logs.append({
        "user": session['user_email'],
        "action": "upload",
        "file": file.filename,
        "manifest_hash": manifest_hash,
        "timestamp": datetime.now().isoformat()
    })
    save_logs(logs)

    flash(f"File uploaded. Manifest hash: {manifest_hash}")
    return redirect(url_for('dashboard'))

@app.route('/retrieve', methods=['POST'])
@login_required
def retrieve():
    manifest_hash = request.form['manifest_hash']
    try:
        manifest = json.load(open(f"manifests/{manifest_hash}.json"))
        ext = os.path.splitext(manifest.get("filename", "file"))[1]
        output = f"recovered_{manifest_hash[:8]}{ext}"
        get_file(manifest_hash, load_private_key("private_key.pem"), os.path.join("temp", output))

        logs = load_logs()
        logs.append({
            "user": session['user_email'],
            "action": "download",
            "file": output,
            "manifest_hash": manifest_hash,
            "timestamp": datetime.now().isoformat()
        })
        save_logs(logs)

        return redirect(url_for('view_file', filename=output))
    except Exception as e:
        flash(f"Retrieval failed: {e}")
        return redirect(url_for('dashboard'))

@app.route('/view/<filename>')
@login_required
def view_file(filename):
    return render_template('view_file.html', filename=filename)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory("temp", filename, as_attachment=True)

@app.route('/download_uploads')
@login_required
def download_uploads():
    path = os.path.join("user_uploads", f"{session['user_email']}.json")
    if not os.path.exists(path):
        flash("No upload history found.")
        return redirect(url_for('settings'))
    return send_from_directory("user_uploads", os.path.basename(path), as_attachment=True)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    email = session['user_email']
    current = request.form['current_password']
    new = request.form['new_password']
    confirm = request.form['confirm_password']
    users = load_users()

    if not check_password_hash(users[email]['password'], current):
        flash("Current password is incorrect.")
    elif new != confirm:
        flash("New passwords do not match.")
    else:
        users[email]['password'] = generate_password_hash(new)
        save_users(users)
        flash("Password updated successfully.")
    return redirect(url_for('settings'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = load_users().get(session['user_email'])
    return render_template('settings.html', user=user, user_role=user.get('role', 'user'))

@app.route('/admin')
@login_required
@role_required('admin')
def admin_console():
    return render_template('admin.html', logs=load_logs(), dht=load_dht())

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.route('/delete_account')
@login_required
def delete_account():
    email = session['user_email']
    users = load_users()
    logs = load_logs()
    if email in users:
        del users[email]
    save_users(users)

    user_file = os.path.join("user_uploads", f"{email}.json")
    if os.path.exists(user_file):
        os.remove(user_file)

    logs.append({
        "user": email,
        "action": "delete_account",
        "file": "-",
        "manifest_hash": "-",
        "timestamp": datetime.now().isoformat()
    })
    save_logs(logs)

    session.clear()
    flash("Your account has been deleted.")
    return redirect(url_for('login'))

@app.route('/manage-users')
@login_required
@role_required('admin')
def manage_users():
    users = load_users()
    return render_template('manage_users.html', users=users)

@app.route('/promote/<email>')
@login_required
@role_required('admin')
def promote_user(email):
    users = load_users()
    if email in users:
        users[email]['role'] = 'admin'
        save_users(users)
        flash(f"{email} has been promoted to admin.")
    else:
        flash("User not found.")
    return redirect(url_for('manage_users'))

@app.route('/demote/<email>')
@login_required
@role_required('admin')
def demote_user(email):
    users = load_users()
    if email in users and users[email]['role'] == 'admin':
        if email == session.get('user_email'):
            flash("You cannot demote yourself.")
        else:
            users[email]['role'] = 'user'
            save_users(users)
            flash(f"{email} has been demoted to user.")
    else:
        flash("User not found or not an admin.")
    return redirect(url_for('manage_users'))

# ---------------- Main ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
