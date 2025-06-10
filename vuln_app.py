from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

home_page = '''
<!doctype html>
<title>Welcome</title>
<h2>Welcome to the Dummy Site</h2>
<p>This is a deliberately vulnerable site for SQL injection and XSS testing.</p>
<p><a href="/login">Go to Login Page</a></p>
<p><a href="/links">Go to Links Page</a></p>
<p><a href="/profile">Go to Profile Lookup</a></p>
'''

login_form = '''
<!doctype html>
<title>Login</title>
<h2>Login</h2>
<form method="post">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
<p>{{ message }}</p>
'''

profile_form = '''
<!doctype html>
<title>Profile</title>
<h2>Profile Lookup</h2>
<form method="get">
  Username: <input type="text" name="username"><br>
  <input type="submit" value="Lookup">
</form>
{% if result %}<p>{{ result|safe }}</p>{% endif %}
'''

links_page = '''
<!doctype html>
<title>Links</title>
<h2>Links Page</h2>
<p>Test crawling with many links:</p>
<ul>
  <li><a href="/login">Login Page</a></li>
  <li><a href="/profile">Profile Lookup</a></li>
  <li><a href="/">Home</a></li>
  <li><a href="/links">Links (this page)</a></li>
  <li><a href="/profile?username=admin">Profile for admin</a></li>
  <li><a href="/profile?username=guest">Profile for guest</a></li>
</ul>
'''

# Ensure users.db exists and has the required users
def initialize_db():
    if not os.path.exists('users.db'):
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
        c.execute('INSERT OR IGNORE INTO users (id, username, password) VALUES (1, "admin", "admin123")')
        c.execute('INSERT OR IGNORE INTO users (id, username, password) VALUES (2, "user", "userpass")')
        c.execute('INSERT OR IGNORE INTO users (id, username, password) VALUES (3, "guest", "guest123")')
        c.execute('INSERT OR IGNORE INTO users (id, username, password) VALUES (4, "root", "toor")')
        conn.commit()
        conn.close()

initialize_db()

@app.route('/', methods=['GET'])
def home():
    return render_template_string(home_page)

@app.route('/login', methods=['GET'])
def login_get():
    return render_template_string(login_form, message="")

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']
    # VULNERABLE SQL QUERY (do not use in production!)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute(query)
        user = c.fetchone()
        if user:
            result = render_template_string(login_form, message="Login successful!")
        else:
            result = render_template_string(login_form, message="Invalid credentials.")
    except Exception as e:
        result = render_template_string(login_form, message=f"SQL Error: {e}")
    conn.close()
    return result

@app.route('/links', methods=['GET'])
def links():
    return render_template_string(links_page)

@app.route('/profile', methods=['GET'])
def profile():
    username = request.args.get('username', '')
    result = ''
    if username:
        # REFLECTED XSS VULNERABILITY (for testing)
        result = f"Profile for user: <b>{username}</b>"
    return render_template_string(profile_form, result=result)

if __name__ == '__main__':
    app.run(debug=True)
