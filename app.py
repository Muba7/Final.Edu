import os
import secrets
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ===== DATABASE =====
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'edutj.db')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'center',
            center_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS centers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            city TEXT DEFAULT '',
            address TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            hours TEXT DEFAULT '',
            description TEXT DEFAULT '',
            instagram TEXT DEFAULT '',
            telegram TEXT DEFAULT '',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            center_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            price TEXT DEFAULT '',
            duration TEXT DEFAULT '',
            location TEXT DEFAULT '',
            description TEXT DEFAULT '',
            teacher_name TEXT DEFAULT '',
            teacher_phone TEXT DEFAULT '',
            teacher_social TEXT DEFAULT '',
            teacher_linkedin TEXT DEFAULT '',
            FOREIGN KEY (center_id) REFERENCES centers(id) ON DELETE CASCADE
        );
    ''')
    # Create admin if not exists
    existing = db.execute("SELECT id FROM users WHERE login = ?", ('adminBratva',)).fetchone()
    if not existing:
        db.execute(
            "INSERT INTO users (login, password_hash, role) VALUES (?, ?, ?)",
            ('adminBratva', generate_password_hash('Otdushi04'), 'admin')
        )
    db.commit()
    db.close()

# ===== FLASK-LOGIN =====
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, login, role, center_id=None):
        self.id = id
        self.login = login
        self.role = role
        self.center_id = center_id

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row:
        return User(row['id'], row['login'], row['role'], row['center_id'])
    return None

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Access denied.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def center_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if current_user.role != 'center':
            flash('Access denied.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# ===== PUBLIC ROUTES =====

@app.route('/')
def index():
    db = get_db()
    centers = db.execute("SELECT * FROM centers WHERE is_active = 1 ORDER BY name").fetchall()
    centers_data = []
    for c in centers:
        courses = db.execute("SELECT * FROM courses WHERE center_id = ?", (c['id'],)).fetchall()
        centers_data.append({
            'id': c['id'], 'name': c['name'], 'city': c['city'],
            'address': c['address'], 'phone': c['phone'], 'hours': c['hours'],
            'description': c['description'], 'instagram': c['instagram'],
            'telegram': c['telegram'],
            'courses': [dict(cr) for cr in courses]
        })
    return render_template('index.html', centers=centers_data)

@app.route('/api/centers')
def api_centers():
    db = get_db()
    centers = db.execute("SELECT * FROM centers WHERE is_active = 1 ORDER BY name").fetchall()
    result = []
    for c in centers:
        courses = db.execute("SELECT * FROM courses WHERE center_id = ?", (c['id'],)).fetchall()
        result.append({
            'id': c['id'], 'name': c['name'], 'city': c['city'],
            'address': c['address'], 'phone': c['phone'], 'hours': c['hours'],
            'description': c['description'], 'instagram': c['instagram'],
            'telegram': c['telegram'],
            'courses': [dict(cr) for cr in courses]
        })
    return jsonify(result)

# ===== AUTH ROUTES =====

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_panel'))
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        login_input = request.form.get('login', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE login = ?", (login_input,)).fetchone()
        if row and check_password_hash(row['password_hash'], password):
            user = User(row['id'], row['login'], row['role'], row['center_id'])
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        flash('Invalid login or password', 'error')
    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ===== CENTER DASHBOARD =====

@app.route('/dashboard')
@center_required
def dashboard():
    db = get_db()
    center = db.execute("SELECT * FROM centers WHERE id = ?", (current_user.center_id,)).fetchone()
    courses = db.execute("SELECT * FROM courses WHERE center_id = ? ORDER BY id", (current_user.center_id,)).fetchall()
    return render_template('dashboard.html', center=dict(center), courses=[dict(c) for c in courses])

@app.route('/dashboard/save-info', methods=['POST'])
@center_required
def save_center_info():
    db = get_db()
    db.execute('''UPDATE centers SET name=?, city=?, address=?, phone=?, hours=?,
                  description=?, instagram=?, telegram=? WHERE id=?''',
        (request.form.get('name',''), request.form.get('city',''),
         request.form.get('address',''), request.form.get('phone',''),
         request.form.get('hours',''), request.form.get('description',''),
         request.form.get('instagram',''), request.form.get('telegram',''),
         current_user.center_id))
    db.commit()
    flash('Center info saved!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard/add-course', methods=['POST'])
@center_required
def add_course():
    db = get_db()
    db.execute('''INSERT INTO courses (center_id, name, price, duration, location, description,
                  teacher_name, teacher_phone, teacher_social, teacher_linkedin)
                  VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (current_user.center_id, request.form.get('course_name',''),
         request.form.get('price',''), request.form.get('duration',''),
         request.form.get('location',''), request.form.get('course_description',''),
         request.form.get('teacher_name',''), request.form.get('teacher_phone',''),
         request.form.get('teacher_social',''), request.form.get('teacher_linkedin','')))
    db.commit()
    flash('Course added!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard/edit-course/<int:course_id>', methods=['POST'])
@center_required
def edit_course(course_id):
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id = ? AND center_id = ?",
                        (course_id, current_user.center_id)).fetchone()
    if not course:
        flash('Course not found.', 'error')
        return redirect(url_for('dashboard'))
    db.execute('''UPDATE courses SET name=?, price=?, duration=?, location=?, description=?,
                  teacher_name=?, teacher_phone=?, teacher_social=?, teacher_linkedin=? WHERE id=?''',
        (request.form.get('course_name',''), request.form.get('price',''),
         request.form.get('duration',''), request.form.get('location',''),
         request.form.get('course_description',''), request.form.get('teacher_name',''),
         request.form.get('teacher_phone',''), request.form.get('teacher_social',''),
         request.form.get('teacher_linkedin',''), course_id))
    db.commit()
    flash('Course updated!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard/delete-course/<int:course_id>', methods=['POST'])
@center_required
def delete_course(course_id):
    db = get_db()
    db.execute("DELETE FROM courses WHERE id = ? AND center_id = ?",
               (course_id, current_user.center_id))
    db.commit()
    flash('Course removed.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard/change-password', methods=['POST'])
@center_required
def change_password():
    old_pw = request.form.get('old_password','')
    new_pw = request.form.get('new_password','')
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()
    if not check_password_hash(row['password_hash'], old_pw):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('dashboard'))
    if len(new_pw) < 6:
        flash('Password must be at least 6 characters.', 'error')
        return redirect(url_for('dashboard'))
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(new_pw), current_user.id))
    db.commit()
    flash('Password changed!', 'success')
    return redirect(url_for('dashboard'))

# ===== ADMIN PANEL =====

@app.route('/admin')
@admin_required
def admin_panel():
    db = get_db()
    centers = db.execute("SELECT * FROM centers ORDER BY created_at DESC").fetchall()
    centers_data = []
    for c in centers:
        user = db.execute("SELECT login FROM users WHERE center_id = ?", (c['id'],)).fetchone()
        course_count = db.execute("SELECT COUNT(*) as cnt FROM courses WHERE center_id = ?", (c['id'],)).fetchone()
        centers_data.append({
            **dict(c),
            'login': user['login'] if user else '—',
            'course_count': course_count['cnt']
        })
    return render_template('admin.html', centers=centers_data)

@app.route('/admin/add-center', methods=['POST'])
@admin_required
def add_center():
    name = request.form.get('name', '').strip()
    login_input = request.form.get('login', '').strip()
    password = request.form.get('password', '').strip()
    city = request.form.get('city', '').strip()

    if not name or not login_input or not password:
        flash('Name, login, and password are required.', 'error')
        return redirect(url_for('admin_panel'))

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE login = ?", (login_input,)).fetchone()
    if existing:
        flash('This login already exists.', 'error')
        return redirect(url_for('admin_panel'))

    cursor = db.execute("INSERT INTO centers (name, city) VALUES (?, ?)", (name, city))
    center_id = cursor.lastrowid
    db.execute("INSERT INTO users (login, password_hash, role, center_id) VALUES (?, ?, 'center', ?)",
               (login_input, generate_password_hash(password), center_id))
    db.commit()
    flash(f'Center "{name}" created! Login: {login_input}', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle-center/<int:center_id>', methods=['POST'])
@admin_required
def toggle_center(center_id):
    db = get_db()
    center = db.execute("SELECT is_active FROM centers WHERE id = ?", (center_id,)).fetchone()
    if center:
        new_status = 0 if center['is_active'] else 1
        db.execute("UPDATE centers SET is_active = ? WHERE id = ?", (new_status, center_id))
        db.commit()
        flash('Center status updated.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete-center/<int:center_id>', methods=['POST'])
@admin_required
def delete_center(center_id):
    db = get_db()
    db.execute("DELETE FROM users WHERE center_id = ?", (center_id,))
    db.execute("DELETE FROM courses WHERE center_id = ?", (center_id,))
    db.execute("DELETE FROM centers WHERE id = ?", (center_id,))
    db.commit()
    flash('Center deleted.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/change-password', methods=['POST'])
@admin_required
def admin_change_password():
    old_pw = request.form.get('old_password','')
    new_pw = request.form.get('new_password','')
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()
    if not check_password_hash(row['password_hash'], old_pw):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('admin_panel'))
    if len(new_pw) < 6:
        flash('Password must be at least 6 characters.', 'error')
        return redirect(url_for('admin_panel'))
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(new_pw), current_user.id))
    db.commit()
    flash('Admin password changed!', 'success')
    return redirect(url_for('admin_panel'))

# ===== INIT & RUN =====
init_db()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
