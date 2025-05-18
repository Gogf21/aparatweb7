from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import base64
import hashlib
from db import create_connection
import json

def authenticate_admin(handler):
    auth_header = handler.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        handler.send_response(401)
        handler.send_header('WWW-Authenticate', 'Basic realm="Admin Panel"')
        handler.end_headers()
        return False
    
    try:
        credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
        username, password = credentials.split(':', 1)
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Admins WHERE username = %s AND password_hash = %s", 
                      (username, password_hash))
        if not cursor.fetchone():
            handler.send_response(401)
            handler.send_header('WWW-Authenticate', 'Basic realm="Admin Panel"')
            handler.end_headers()
            return False
        return True
    except:
        handler.send_response(401)
        handler.send_header('WWW-Authenticate', 'Basic realm="Admin Panel"')
        handler.end_headers()
        return False

class AdminHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not authenticate_admin(self):
            return
            
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/admin':
            self.serve_admin_dashboard()
        elif parsed_path.path == '/admin/users':
            self.serve_users_list()
        elif parsed_path.path == '/admin/stats':
            self.serve_language_stats()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')

    def do_POST(self):
        if not authenticate_admin(self):
            return
            
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/admin/delete':
            self.handle_delete_user()
        elif parsed_path.path == '/admin/update':
            self.handle_admin_update()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')

    def serve_admin_dashboard(self):
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Admin Dashboard</title>
                <link rel="stylesheet" href="/static/styles.css">
            </head>
            <body>
                <div class="admin-container">
                    <h1>Admin Dashboard</h1>
                    <nav>
                        <a href="/admin/users">Manage Users</a>
                        <a href="/admin/stats">Language Statistics</a>
                    </nav>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        except Exception as e:
            self.send_error(500, str(e))

    def serve_users_list(self):
        try:
            conn = create_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT u.id, u.username, u.first_name, u.last_name, u.email, 
                       array_agg(pl.name) as languages
                FROM Users u
                LEFT JOIN UserProgrammingLanguages upl ON u.id = upl.user_id
                LEFT JOIN ProgrammingLanguages pl ON upl.language_id = pl.id
                GROUP BY u.id
                ORDER BY u.id
            """)
            
            users = []
            for row in cursor:
                users.append({
                    'id': row[0],
                    'username': row[1],
                    'name': f"{row[2]} {row[3]}",
                    'email': row[4],
                    'languages': row[5] if row[5] and row[5][0] else []
                })
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>User Management</title>
                <link rel="stylesheet" href="/static/styles.css">
            </head>
            <body>
                <div class="admin-container">
                    <h1>User Management</h1>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Languages</th>
                            <th>Actions</th>
                        </tr>
            """
            
            for user in users:
                html += f"""
                <tr>
                    <td>{user['id']}</td>
                    <td>{user['username']}</td>
                    <td>{user['name']}</td>
                    <td>{user['email']}</td>
                    <td>{', '.join(user['languages'])}</td>
                    <td>
                        <a href="/admin/edit/{user['id']}">Edit</a>
                        <form action="/admin/delete" method="post" style="display:inline;">
                            <input type="hidden" name="user_id" value="{user['id']}">
                            <button type="submit">Delete</button>
                        </form>
                    </td>
                </tr>
                """
            
            html += """
                    </table>
                    <a href="/admin">Back to Dashboard</a>
                </div>
            </body>
            </html>
            """
            
            self.wfile.write(html.encode('utf-8'))
        except Exception as e:
            self.send_error(500, str(e))
        finally:
            cursor.close()
            conn.close()

    def serve_language_stats(self):
        try:
            conn = create_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT pl.name, COUNT(upl.user_id) as user_count
                FROM ProgrammingLanguages pl
                LEFT JOIN UserProgrammingLanguages upl ON pl.id = upl.language_id
                GROUP BY pl.name
                ORDER BY user_count DESC
            """)
            
            stats = [{'language': row[0], 'count': row[1]} for row in cursor]
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Language Statistics</title>
                <link rel="stylesheet" href="/static/styles.css">
            </head>
            <body>
                <div class="admin-container">
                    <h1>Language Statistics</h1>
                    <table>
                        <tr>
                            <th>Language</th>
                            <th>User Count</th>
                        </tr>
            """
            
            for stat in stats:
                html += f"""
                <tr>
                    <td>{stat['language']}</td>
                    <td>{stat['count']}</td>
                </tr>
                """
            
            html += """
                    </table>
                    <a href="/admin">Back to Dashboard</a>
                </div>
            </body>
            </html>
            """
            
            self.wfile.write(html.encode('utf-8'))
        except Exception as e:
            self.send_error(500, str(e))
        finally:
            cursor.close()
            conn.close()

    def handle_delete_user(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = parse_qs(post_data)
            user_id = data['user_id'][0]
            
            conn = create_connection()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM UserProgrammingLanguages WHERE user_id = %s", (user_id,))
            cursor.execute("DELETE FROM Users WHERE id = %s", (user_id,))
            conn.commit()
            
            self.send_response(303)
            self.send_header('Location', '/admin/users')
            self.end_headers()
        except Exception as e:
            conn.rollback()
            self.send_error(500, str(e))
        finally:
            cursor.close()
            conn.close()

    def handle_admin_update(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = parse_qs(post_data)
            
            user_id = data['user_id'][0]
            fullname = data['fullname'][0]
            email = data['email'][0]
            languages = data.get('language', [])
            
            # Split fullname into parts
            parts = fullname.split()
            first_name = parts[0] if len(parts) > 0 else ''
            last_name = parts[1] if len(parts) > 1 else ''
            middle_name = parts[2] if len(parts) > 2 else None
            
            conn = create_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE Users
                SET first_name = %s, last_name = %s, middle_name = %s, email = %s
                WHERE id = %s
            """, (first_name, last_name, middle_name, email, user_id))
            
            cursor.execute("DELETE FROM UserProgrammingLanguages WHERE user_id = %s", (user_id,))
            
            for lang in languages:
                cursor.execute("""
                    INSERT INTO UserProgrammingLanguages (user_id, language_id)
                    VALUES (%s, (SELECT id FROM ProgrammingLanguages WHERE name = %s))
                """, (user_id, lang))
            
            conn.commit()
            
            self.send_response(303)
            self.send_header('Location', '/admin/users')
            self.end_headers()
        except Exception as e:
            conn.rollback()
            self.send_error(500, str(e))
        finally:
            cursor.close()
            conn.close()
