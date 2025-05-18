
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import html
from db import save_user, get_user_by_id, update_user, get_user_by_credentials
from validators import validate_form_data, validate_login_form
import os
import json
from http import cookies
import time
from datetime import datetime, timedelta
import hmac
import hashlib
import base64
import secrets
import uuid
import re

JWT_SECRET = secrets.token_hex(32)
TOKEN_EXPIRATION = 3600

class RequestHandler(BaseHTTPRequestHandler):
    def _set_secure_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Content-Security-Policy', "default-src 'self'")
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Server', 'Custom Server')

    def _set_cookies(self, cookie_data, max_age=None, expires=None):
        cookie = cookies.SimpleCookie()
        for key, value in cookie_data.items():
            cookie[key] = value
            cookie[key]['path'] = '/'
            if max_age:
                cookie[key]['max-age'] = max_age
            if expires:
                cookie[key]['expires'] = expires
            cookie[key]['httponly'] = True
            cookie[key]['secure'] = True  # Для HTTPS
            cookie[key]['samesite'] = 'Strict'
        self.send_header('Set-Cookie', cookie.output(header=''))

    def _get_cookies(self):
        if 'Cookie' in self.headers:
            cookie = cookies.SimpleCookie()
            cookie.load(self.headers['Cookie'])
            return {k: v.value for k, v in cookie.items()}
        return {}

    def _generate_csrf_token(self):
        token = secrets.token_hex(32)
        self._set_cookies({'csrf_token': token}, max_age=3600)
        return token

    def _validate_csrf(self, post_data):
        cookies = self._get_cookies()
        if 'csrf_token' not in cookies:
            return False
        return 'csrf_token' in post_data and post_data['csrf_token'][0] == cookies['csrf_token']

    def _clear_auth_cookies(self):
        self._set_cookies({'auth_token': '', 'csrf_token': ''}, max_age=0)

    def _generate_jwt(self, user_id):
        header = {
            "alg": "HS256",
            "typ": "JWT"
        }
        payload = {
            "sub": user_id,
            "exp": int(time.time()) + TOKEN_EXPIRATION,
            "iat": int(time.time())
        }
        
        encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        signature = hmac.new(
            JWT_SECRET.encode(),
            f"{encoded_header}.{encoded_payload}".encode(),
            hashlib.sha256
        ).digest()
        encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

    def _verify_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
                
            encoded_header, encoded_payload, encoded_signature = parts
            signature = base64.urlsafe_b64decode(encoded_signature + '==')
            
            expected_signature = hmac.new(
                JWT_SECRET.encode(),
                f"{encoded_header}.{encoded_payload}".encode(),
                hashlib.sha256
            ).digest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return None
                
            payload = json.loads(base64.urlsafe_b64decode(encoded_payload + '==').decode())
            
            if payload['exp'] < int(time.time()):
                return None
                
            return payload['sub']
        except:
            return None

    def _get_current_user(self):
        cookies = self._get_cookies()
        if 'auth_token' not in cookies:
            return None
            
        user_id = self._verify_jwt(cookies['auth_token'])
        if not user_id:
            return None
            
        return get_user_by_id(user_id)

    def _prepare_user_data(self, data):
        fullname_parts = data['fullname'][0].strip().split()
        return {
            'first_name': fullname_parts[0] if len(fullname_parts) > 0 else '',
            'last_name': fullname_parts[1] if len(fullname_parts) > 1 else '',
            'middle_name': fullname_parts[2] if len(fullname_parts) > 2 else None,
            'phone': data['phone'][0].strip(),
            'email': data['email'][0].strip(),
            'birthdate': data['birthdate'][0],
            'gender': data['gender'][0],
            'biography': data['bio'][0].strip(),
            'languages': data.get('language', [])
        }

    def do_GET(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/':
            self.serve_main_page()
        elif parsed_path.path == '/login':
            self.serve_login_page()
        elif parsed_path.path == '/registration':
            self.serve_registration_page()
        elif parsed_path.path == '/edit':
            self.serve_edit_page()
        elif parsed_path.path == '/logout':
            self.handle_logout()
        elif parsed_path.path.startswith('/static/'):
            self.serve_static_file(parsed_path.path)
        else:
            self.send_response(404)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'404 Not Found')

    def do_POST(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/submit':
            self.handle_form_submission()
        elif parsed_path.path == '/login':
            self.handle_login()
        elif parsed_path.path == '/update':
            self.handle_update()
        elif parsed_path.path == '/logout':
            self.handle_logout()
        else:
            self.send_response(404)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'404 Not Found')

    def serve_main_page(self):
        try:
            with open('templates/main.html', 'r', encoding='utf-8') as file:
                html_content = file.read()
            
            user = self._get_current_user()
            if user:
                auth_section = f"""
                <div class="auth-info">
                    <p>Вы вошли как {html.escape(user['username'])}</p>
                    <a href="/edit">Редактировать данные</a>
                    <form action="/logout" method="post">
                        <input type="hidden" name="csrf_token" value="{self._generate_csrf_token()}">
                        <button type="submit">Выйти</button>
                    </form>
                </div>
                """
            else:
                auth_section = """
                <div class="auth-info">
                    <p>Вы не авторизованы</p>
                    <div class="auth-actions">
                        <a href="/login">Войти</a>
                        <a href="/registration">Зарегистрироваться</a>
                    </div>
                </div>
                """
            
            html_content = html_content.replace('<!-- AUTH_SECTION -->', auth_section)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

    def serve_login_page(self, errors=None):
        try:
            with open('templates/login.html', 'r', encoding='utf-8') as file:
                html_content = file.read()
            
            csrf_token = self._generate_csrf_token()
            html_content = html_content.replace(
                '</form>',
                f'<input type="hidden" name="csrf_token" value="{csrf_token}"></form>'
            )
            
            if errors:
                if 'auth_error' in errors:
                    html_content = html_content.replace(
                        '<h2>Вход в систему</h2>',
                        f'<h2>Вход в систему</h2>\n<div class="error-message">{html.escape(errors["auth_error"])}</div>'
                    )
                
                for field in ['username', 'password']:
                    if field in errors:
                        html_content = html_content.replace(
                            f'name="{field}"',
                            f'name="{field}" class="error-field"'
                        )
                        error_div = f'<div class="error-message">{html.escape(errors[field])}</div>'
                        html_content = html_content.replace(
                            f'<label for="{field}">',
                            f'{error_div}<label for="{field}">'
                        )
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

    def serve_registration_page(self, errors=None, form_data=None):
        try:
            with open('templates/registration.html', 'r', encoding='utf-8') as file:
                html_content = file.read()
            
            csrf_token = self._generate_csrf_token()
            html_content = html_content.replace(
                '</form>',
                f'<input type="hidden" name="csrf_token" value="{csrf_token}"></form>'
            )
            
            if errors:
                if 'server_error' in errors:
                    html_content = html_content.replace(
                        '<h2>Форма регистрации</h2>',
                        f'<h2>Форма регистрации</h2>\n<div class="server-error">{html.escape(errors["server_error"])}</div>'
                    )
                
                for field, error in errors.items():
                    if field != 'server_error':
                        html_content = html_content.replace(
                            f'name="{field}"',
                            f'name="{field}" class="error-field"'
                        )
                        error_div = f'<div class="error-message">{html.escape(error)}</div>'
                        html_content = html_content.replace(
                            f'<label for="{field}">',
                            f'{error_div}<label for="{field}">'
                        )
            
            if form_data:
                for field in ['fullname', 'phone', 'email', 'birthdate', 'bio']:
                    if field in form_data:
                        value = html.escape(form_data[field][0])
                        html_content = html_content.replace(
                            f'name="{field}"',
                            f'name="{field}" value="{value}"'
                        )
                
                if 'gender' in form_data:
                    gender = form_data['gender'][0]
                    html_content = html_content.replace(
                        f'value="{gender}"',
                        f'value="{gender}" checked'
                    )
                
                if 'language' in form_data:
                    for lang in form_data['language']:
                        html_content = html_content.replace(
                            f'value="{lang}"',
                            f'value="{lang}" selected'
                        )
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

    def serve_edit_page(self, errors=None, form_data=None):
        user = self._get_current_user()
        if not user:
            self.send_response(303)
            self.send_header('Location', '/login')
            self.end_headers()
            return
            
        try:
            with open('templates/edit.html', 'r', encoding='utf-8') as file:
                html_content = file.read()
            
            csrf_token = self._generate_csrf_token()
            html_content = html_content.replace(
                '</form>',
                f'<input type="hidden" name="csrf_token" value="{csrf_token}"></form>'
            )
            
            if not form_data:
                form_data = {
                    'fullname': [f"{user['first_name']} {user['last_name']} {user['middle_name'] if user['middle_name'] else ''}".strip()],
                    'phone': [user['phone']],
                    'email': [user['email']],
                    'birthdate': [user['birthdate']],
                    'gender': [user['gender']],
                    'bio': [user['biography']],
                    'language': user['languages']
                }
            
            for field in ['fullname', 'phone', 'email', 'birthdate', 'bio']:
                if field in form_data:
                    value = html.escape(form_data[field][0])
                    html_content = html_content.replace(
                        f'name="{field}"',
                        f'name="{field}" value="{value}"'
                    )
            
            if 'gender' in form_data:
                gender = form_data['gender'][0]
                html_content = html_content.replace(
                    f'value="{gender}"',
                    f'value="{gender}" checked'
                )
            
            if 'language' in form_data:
                for lang in form_data['language']:
                    html_content = html_content.replace(
                        f'value="{lang}"',
                        f'value="{lang}" selected'
                    )
            
            if errors:
                if 'server_error' in errors:
                    html_content = html_content.replace(
                        '<h2>Редактирование данных</h2>',
                        f'<h2>Редактирование данных</h2>\n<div class="server-error">{html.escape(errors["server_error"])}</div>'
                    )
                
                for field, error in errors.items():
                    if field != 'server_error':
                        html_content = html_content.replace(
                            f'name="{field}"',
                            f'name="{field}" class="error-field"'
                        )
                        error_div = f'<div class="error-message">{html.escape(error)}</div>'
                        html_content = html_content.replace(
                            f'<label for="{field}">',
                            f'{error_div}<label for="{field}">'
                        )
            
            if 'success=1' in self.path:
                html_content = html_content.replace(
                    '<h2>Редактирование данных</h2>',
                    '<h2>Редактирование данных</h2>\n<div class="success-message">Данные успешно обновлены!</div>'
                )
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

    def serve_credentials_page(self, username, password, user_id):
        credentials_html = f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>Успешная регистрация</title>
            <link rel="stylesheet" href="/static/styles.css">
        </head>
        <body>
            <div class="success-container">
                <h2>Регистрация завершена успешно!</h2>
                <p>Ваш ID: {html.escape(str(user_id))}</p>
                <div class="credentials">
                    <h3>Ваши учетные данные:</h3>
                    <p><strong>Логин:</strong> {html.escape(username)}</p>
                    <p><strong>Пароль:</strong> {html.escape(password)}</p>
                    <p class="warning">Сохраните эти данные! Пароль нельзя восстановить!</p>
                </div>
                <div class="actions">
                    <a href="/login">Войти в систему</a>
                    <a href="/">На главную</a>
                </div>
            </div>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self._set_secure_headers()
        self.end_headers()
        self.wfile.write(credentials_html.encode('utf-8'))

    def serve_static_file(self, filepath):
        if not filepath.startswith('static/') or '..' in filepath:
            self.send_response(403)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'403 Forbidden')
            return
        
        content_types = {
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg'
        }
        
        ext = os.path.splitext(filepath)[1].lower()
        content_type = content_types.get(ext, 'application/octet-stream')
        
        try:
            with open(filepath, 'rb') as file:
                self.send_response(200)
                self.send_header('Content-type', content_type)
                self._set_secure_headers()
                self.end_headers()
                self.wfile.write(file.read())
        except FileNotFoundError:
            self.send_response(404)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'404 Not Found')
        except Exception as e:
            self.send_response(500)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

    def handle_form_submission(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = parse_qs(post_data)
        
        if not self._validate_csrf(data):
            self.send_response(403)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'Invalid CSRF token')
            return
        
        errors = validate_form_data(data)
        
        if errors:
            self.serve_registration_page(errors, data)
        else:
            try:
                username = str(uuid.uuid4())[:8]
                password = secrets.token_urlsafe(8)
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                
                user_data = self._prepare_user_data(data)
                user_data['username'] = username
                user_data['password_hash'] = password_hash
                
                user_id = save_user(user_data)
                
                self.serve_credentials_page(username, password, user_id)
            except Exception as e:
                self.serve_registration_page({'server_error': str(e)}, data)

    def handle_login(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = parse_qs(post_data)
        
        if not self._validate_csrf(data):
            self.send_response(403)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'Invalid CSRF token')
            return
            
        errors = validate_login_form(data)
        
        if errors:
            self.serve_login_page(errors)
        else:
            username = data['username'][0]
            password = data['password'][0]
            
            user = get_user_by_credentials(username, password)
            if user:
                token = self._generate_jwt(user['id'])
                expires = (datetime.now() + timedelta(seconds=TOKEN_EXPIRATION)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                
                self.send_response(303)
                self._set_cookies({'auth_token': token}, expires=expires)
                self.send_header('Location', '/edit')
                self.end_headers()
            else:
                self.serve_login_page({'auth_error': 'Неверные учетные данные'})

    def handle_update(self):
        user = self._get_current_user()
        if not user:
            self.send_response(303)
            self.send_header('Location', '/login')
            self.end_headers()
            return
            
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = parse_qs(post_data)
        
        if not self._validate_csrf(data):
            self.send_response(403)
            self._set_secure_headers()
            self.end_headers()
            self.wfile.write(b'Invalid CSRF token')
            return
        
        errors = validate_form_data(data)
        
        if errors:
            self.serve_edit_page(errors, data)
        else:
            try:
                user_data = self._prepare_user_data(data)
                update_user(user['id'], user_data)
                
                self.send_response(303)
                self.send_header('Location', '/edit?success=1')
                self.end_headers()
            except Exception as e:
                self.serve_edit_page({'server_error': str(e)}, data)

    def handle_logout(self):
        self._clear_auth_cookies()
        self.send_response(303)
        self.send_header('Location', '/')
        self.end_headers()

def run_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RequestHandler)
    print('Сервер запущен на порту 8000...')
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
