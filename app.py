from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from cryptography.fernet import Fernet
import bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Function to generate a new Fernet key (use this once to generate your key)


def generate_key():
    return Fernet.generate_key()


# Encryption key (store safely) - This is a properly generated Fernet key
# Replace with your real key from generate_key()
key = b'fZ8wMjS5Q3K7vR2nL9mP6cT4xU1yE8oI3dF7gH2sA5B='
fernet = Fernet(key)

# ----------- User Class ----------- #


class User(UserMixin):
    def __init__(self, id_, username):
        self.id = id_
        self.username = username

# ----------- DB Setup ----------- #


def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            site TEXT,
            username TEXT,
            password TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    # Check if user_id column exists, if not add it
    c.execute("PRAGMA table_info(passwords)")
    columns = [column[1] for column in c.fetchall()]
    if 'user_id' not in columns:
        c.execute("ALTER TABLE passwords ADD COLUMN user_id INTEGER")
    
    conn.commit()
    conn.close()


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1])
    return None

# ----------- Routes ----------- #


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.hashpw(
            request.form['password'].encode(), bcrypt.gensalt())

        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already taken"
        conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user[2]):
            user_obj = User(user[0], user[1])
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials"
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT id, site, username, password FROM passwords WHERE user_id = ?", (current_user.id,))
    data = c.fetchall()
    conn.close()
    
    decrypted_data = []
    for row in data:
        try:
            # row[1] = site, row[2] = username, row[3] = password
            encrypted_password = row[3]
            if isinstance(encrypted_password, str):
                decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
            else:
                # Handle case where password might be stored differently
                decrypted_password = "Error: Invalid password format"
            decrypted_data.append((row[1], row[2], decrypted_password))
        except Exception as e:
            # Handle decryption errors gracefully
            decrypted_data.append((row[1], row[2], "Error: Could not decrypt"))
    
    return render_template('dashboard.html', data=decrypted_data)


@app.route('/add', methods=['POST'])
@login_required
def add():
    site = request.form['site']
    username = request.form['username']
    password = fernet.encrypt(request.form['password'].encode()).decode()

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("INSERT INTO passwords (user_id, site, username, password) VALUES (?, ?, ?, ?)",
              (current_user.id, site, username, password))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
