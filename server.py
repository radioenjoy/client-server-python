from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import mysql.connector
import uuid
from datetime import datetime, timedelta
import random
import string
import hashlib

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="g7KDhA123DyN",
    database="registration_project"
)
cursor = db.cursor(dictionary=True)
sessions = {}


def generate_captcha():
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    cursor.execute("INSERT INTO captcha (captcha_code) VALUES (%s)", (code,))
    db.commit()
    return code

def validate_captcha(code):
    cursor.execute("SELECT * FROM captcha WHERE captcha_code=%s AND is_used=FALSE", (code,))
    row = cursor.fetchone()
    if row:
        cursor.execute("UPDATE captcha SET is_used=TRUE WHERE id=%s", (row['id'],))
        db.commit()
        return True
    return False

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


class MyHandler(BaseHTTPRequestHandler):

    def get_user_from_session(self):
        cookie = self.headers.get('Cookie')
        if cookie and 'session_token=' in cookie:
            token = cookie.split('session_token=')[1]
            cursor.execute("SELECT user_id FROM sessions WHERE session_token=%s AND expires_at > NOW()", (token,))
            row = cursor.fetchone()
            if row:
                return row['user_id'], token
        return None, None

    def do_GET(self):
        user_id, session_token = self.get_user_from_session()

        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            if user_id:
                cursor.execute("SELECT first_name, last_name, email FROM users WHERE id=%s", (user_id,))
                user = cursor.fetchone()
                html = f"""
                <h1>Добре дошъл, {user['first_name']} {user['last_name']}</h1>
                <a href='/edit'>Промяна на данни</a> |
                <a href='/logout'>Изход</a>
                """
            else:
                html = """
                <h1>Добре дошъл!</h1>
                <a href='/register'>Регистрация</a> |
                <a href='/login'>Вход</a>
                """
            self.wfile.write(html.encode('utf-8'))

        elif self.path == '/register':
            captcha_code = generate_captcha()
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            html = f"""
            <h1>Регистрация</h1>
            <form method='POST' action='/register'>
                Име: <input type='text' name='first_name'><br>
                Фамилия: <input type='text' name='last_name'><br>
                Имейл: <input type='text' name='email'><br>
                Парола: <input type='password' name='password'><br>
                Потвърди Парола: <input type='password' name='password2'><br>
                CAPTCHA: <b>{captcha_code}</b><br>
                Въведи CAPTCHA: <input type='text' name='captcha'><br>
                <input type='submit' value='Регистрация'>
            </form>
            """
            self.wfile.write(html.encode('utf-8'))

        elif self.path == '/login':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            html = """
            <h1>Вход</h1>
            <form method='POST' action='/login'>
                Имейл: <input type='text' name='email'><br>
                Парола: <input type='password' name='password'><br>
                <input type='submit' value='Вход'>
            </form>
            """
            self.wfile.write(html.encode('utf-8'))

        elif self.path == '/logout':
            if session_token:
                cursor.execute("DELETE FROM sessions WHERE session_token=%s", (session_token,))
                db.commit()
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', 'session_token=deleted; Max-Age=0')
            self.end_headers()

        elif self.path == '/edit':
            if not user_id:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            cursor.execute("SELECT first_name, last_name FROM users WHERE id=%s", (user_id,))
            user = cursor.fetchone()
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            html = f"""
            <h1>Промяна на данни</h1>
            <form method='POST' action='/edit'>
                Име: <input type='text' name='first_name' value='{user['first_name']}'><br>
                Фамилия: <input type='text' name='last_name' value='{user['last_name']}'><br>
                Нова парола: <input type='password' name='password'><br>
                Потвърди парола: <input type='password' name='password2'><br>
                <input type='submit' value='Запази'>
            </form>
            """
            self.wfile.write(html.encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = parse_qs(post_data)

        if self.path == '/register':
            first_name = data.get('first_name', [''])[0]
            last_name = data.get('last_name', [''])[0]
            email = data.get('email', [''])[0]
            password = data.get('password', [''])[0]
            password2 = data.get('password2', [''])[0]
            captcha_input = data.get('captcha', [''])[0]

            errors = []
            if not first_name or not last_name: errors.append("Име и фамилия задължителни")
            if "@" not in email: errors.append("Невалиден имейл")
            if len(password) < 6: errors.append("Паролата трябва да е поне 6 символа")
            if password != password2: errors.append("Паролите не съвпадат")
            if not validate_captcha(captcha_input): errors.append("Невалидна CAPTCHA")

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()

            if errors:
                self.wfile.write("<br>".join(errors).encode('utf-8'))
            else:
                try:
                    password_hash = hash_password(password)
                    cursor.execute(
                        "INSERT INTO users (first_name, last_name, email, password_hash) VALUES (%s,%s,%s,%s)",
                        (first_name, last_name, email, password_hash)
                    )
                    db.commit()
                    self.wfile.write("Регистрацията е успешна!".encode('utf-8'))
                except mysql.connector.Error as err:
                    self.wfile.write(f"Грешка: {err}".encode('utf-8'))

        elif self.path == '/login':
            email = data.get('email', [''])[0]
            password = data.get('password', [''])[0]
            password_hash = hash_password(password)

            cursor.execute("SELECT id FROM users WHERE email=%s AND password_hash=%s", (email, password_hash))
            user = cursor.fetchone()

            self.send_response(302 if user else 200)
            if user:
                token = str(uuid.uuid4())
                expires_at = datetime.now() + timedelta(days=1)
                cursor.execute(
                    "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (%s,%s,%s)",
                    (user['id'], token, expires_at)
                )
                db.commit()
                self.send_header('Location', '/')
                self.send_header('Set-Cookie', f'session_token={token}; Path=/')
                self.end_headers()
            else:
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write("Невалиден имейл или парола!".encode('utf-8'))

        elif self.path == '/edit':
            user_id, _ = self.get_user_from_session()
            if not user_id:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            first_name = data.get('first_name', [''])[0]
            last_name = data.get('last_name', [''])[0]
            password = data.get('password', [''])[0]
            password2 = data.get('password2', [''])[0]

            errors = []
            if not first_name or not last_name: errors.append("Име и фамилия задължителни")
            if password and (len(password)<6 or password != password2): errors.append("Паролите не съвпадат или са твърде кратки")

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()

            if errors:
                self.wfile.write("<br>".join(errors).encode('utf-8'))
            else:
                if password:
                    password_hash = hash_password(password)
                    cursor.execute(
                        "UPDATE users SET first_name=%s,last_name=%s,password_hash=%s WHERE id=%s",
                        (first_name, last_name, password_hash, user_id)
                    )
                else:
                    cursor.execute(
                        "UPDATE users SET first_name=%s,last_name=%s WHERE id=%s",
                        (first_name, last_name, user_id)
                    )
                db.commit()
                self.wfile.write("Данните са обновени успешно!".encode('utf-8'))


server = HTTPServer(('localhost', 8000), MyHandler)
print("http://localhost:8000")
server.serve_forever()
