import hashlib
import getpass
from db import create_connection

def create_admin():
    username = input("Enter admin username: ")
    password = getpass.getpass("Enter admin password: ")
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = create_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO Admins (username, password_hash) VALUES (%s, %s)", 
                      (username, password_hash))
        conn.commit()
        print("Admin created successfully!")
    except Exception as e:
        conn.rollback()
        print(f"Error creating admin: {e}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    create_admin()
