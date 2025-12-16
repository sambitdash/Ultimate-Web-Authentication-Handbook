# -----------------------------------------------------------------------------
# Flask server demonstrating basic authentication, cookie-based visit counting,
# and session management.
#
# This module sets up a Flask server with several routes:
# - `/hello`: Returns a simple "Hello, World!" message.
# - `/count`: Tracks the number of visits using a cookie named 'count'.
# - `/session`: Tracks the number of visits per session using a session cookie
#   and an in-memory map.
# - `/basicauth`: Implements HTTP Basic Authentication for the user 'jdoe' with
#   password 'password'.
# 
#   /login
#     GET: Shows a login form. POST: Authenticates user and sets session.
#
#   /resource
#     Protected resource. Only accessible to logged-in users via session.
#
# Endpoints:
#   /hello
#     Responds with "Hello, World!".
#
#   /count
#     Increments and returns the visit count using a cookie named 'count'.
#
#   /session
#     Increments and returns the visit count per session using a session cookie
#     and a server-side map.
#
#   /basicauth
#     Implements HTTP Basic Authentication. Only authenticates user 'jdoe' with
#     password 'password'.
#
#   /login
#     GET: Shows a login form. POST: Authenticates user and sets session.
#
#   /resource
#     Protected resource. Only accessible to logged-in users via session.
#
# Server:
#   Listens on port 8080.
# -----------------------------------------------------------------------------

import base64
import uuid
from flask import Flask, request, make_response, session, redirect
from flask import render_template_string

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# In-memory session visit count map
session_visits = {}

USERNAME = 'jdoe'
PASSWORD = 'password'

def check_auth(auth_header):
  if not auth_header or not auth_header.startswith('Basic '):
    return False
  try:
    encoded = auth_header.split(' ', 1)[1]
    decoded = base64.b64decode(encoded).decode('utf-8')
    username, password = decoded.split(':', 1)
    return username == USERNAME and password == PASSWORD
  except Exception:
    return False

def require_basic_auth(view_func):
  def wrapper(*args, **kwargs):
    auth = request.headers.get('Authorization')
    if not check_auth(auth):
      resp = make_response('Unauthorized', 401)
      resp.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
      return resp
    return view_func(*args, **kwargs)
  wrapper.__name__ = view_func.__name__
  return wrapper

@app.route('/hello')
def hello():
  return 'Hello, World!'

@app.route('/count')
def count():
  count = int(request.cookies.get('count', 0)) + 1
  resp = make_response(f'Visit count: {count}')
  resp.set_cookie('count', str(count), httponly=True)
  return resp

@app.route('/session')
def session_count():
  sid = session.get('sid')
  if not sid:
    sid = str(uuid.uuid4())
    session['sid'] = sid
  session_visits[sid] = session_visits.get(sid, 0) + 1
  return f'Session visit count: {session_visits[sid]}'

@app.route('/basicauth')
@require_basic_auth
def basicauth():
  return 'You are authenticated as jdoe.'

# Simple in-memory user store
users = {'jdoe': 'password'}

@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    username = request.form.get('username')
    password = request.form.get('password')
    if username in users and users[username] == password:
      session['user'] = username
      return redirect('/resource')
    error = 'Invalid credentials'
    return render_template_string('''
      <form method="post">
        <p style="color:red;">{{ error }}</p>
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login">
      </form>
    ''', error=error)
  return render_template_string('''
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <input type="submit" value="Login">
    </form>
  ''')

def login_required(view_func):
  def wrapper(*args, **kwargs):
    if 'user' not in session:
      return redirect('/login')
    return view_func(*args, **kwargs)
  wrapper.__name__ = view_func.__name__
  return wrapper

@app.route('/resource')
@login_required
def resource():
  return f'Protected resource. You are logged in as {session["user"]}.'

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8080, debug=True)
