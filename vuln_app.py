from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

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

@app.route('/', methods=['GET'])
def index():
    return render_template_string(login_form, message="")

@app.route('/', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    # VULNERABLE SQL QUERY (do not use in production!)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Re-create the users table and insert multiple users for each request
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute('INSERT OR IGNORE INTO users (id, username, password) VALUES (1, "admin", "admin123")')
    c.execute('INSERT OR IGNORE INTO users (id, username, password) VALUES (2, "user", "userpass")')
    c.execute('INSERT OR IGNORE INTO users (id, username, password) VALUES (3, "guest", "guest123")')
    c.execute('INSERT OR IGNORE INTO users (id, username, password) VALUES (4, "root", "toor")')
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

if __name__ == '__main__':
    app.run(debug=True)
