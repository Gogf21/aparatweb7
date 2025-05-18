import psycopg2
import os
import hashlib
from typing import Optional, Dict, List, Union
import logging
from datetime import datetime

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_connection():
    try:
        conn = psycopg2.connect(
            host=os.getenv('POSTGRES_HOST', 'localhost'),
            database=os.getenv('POSTGRES_DB', 'webapp_db'),
            user=os.getenv('POSTGRES_USER', 'webapp_user'),
            password=os.getenv('POSTGRES_PASSWORD', 'securepassword'),
            port=os.getenv('POSTGRES_PORT', '5432'),
            sslmode=os.getenv('POSTGRES_SSLMODE', 'prefer'),
            connect_timeout=10
        )
        conn.autocommit = False
        return conn
    except psycopg2.Error as e:
        logger.error(f"Database connection error: {e}")
        raise Exception("Database connection failed")

def execute_safe(cursor, query: str, params: Optional[tuple] = None) -> bool:
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return True
    except psycopg2.Error as e:
        logger.error(f"Database error: {str(e)}")
        return False

def save_user(user_data: Dict) -> Optional[int]:
    conn = None
    cursor = None
    try:
        conn = create_connection()
        cursor = conn.cursor()

        required_fields = ['first_name', 'last_name', 'phone', 'email',
                         'birthdate', 'gender', 'biography', 'username', 'password_hash']
        if not all(field in user_data for field in required_fields):
            logger.error("Missing required fields in user data")
            return None

        user_query = """
            INSERT INTO Users 
            (first_name, last_name, middle_name, phone, email, birthdate, 
             gender, biography, username, password_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        user_params = (
            user_data['first_name'][:50],
            user_data['last_name'][:50],
            user_data.get('middle_name', '')[:50],
            user_data['phone'][:20],
            user_data['email'][:100],
            user_data['birthdate'],
            user_data['gender'],
            user_data['biography'][:500],
            user_data['username'][:50],
            user_data['password_hash']
        )

        if not execute_safe(cursor, user_query, user_params):
            return None

        user_id = cursor.fetchone()[0]

        if 'languages' in user_data and user_data['languages']:
            for lang in user_data['languages']:
                lang_query = """
                    INSERT INTO UserProgrammingLanguages (user_id, language_id)
                    VALUES (%s, (SELECT id FROM ProgrammingLanguages WHERE name = %s))
                    ON CONFLICT DO NOTHING
                """
                if not execute_safe(cursor, lang_query, (user_id, str(lang)[:50])):
                    conn.rollback()
                    return None

        conn.commit()
        return user_id
    except Exception as e:
        logger.error(f"Error saving user: {str(e)}")
        if conn:
            conn.rollback()
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def get_user_by_id(user_id: int) -> Optional[Dict]:
    conn = None
    cursor = None
    try:
        conn = create_connection()
        cursor = conn.cursor()

        query = """
            SELECT u.id, u.first_name, u.last_name, u.middle_name, u.phone, 
                   u.email, u.birthdate, u.gender, u.biography, u.username,
                   array_agg(pl.name) as languages
            FROM Users u
            LEFT JOIN UserProgrammingLanguages upl ON u.id = upl.user_id
            LEFT JOIN ProgrammingLanguages pl ON upl.language_id = pl.id
            WHERE u.id = %s
            GROUP BY u.id
        """
        
        if not execute_safe(cursor, query, (user_id,)):
            return None

        row = cursor.fetchone()
        if not row:
            return None

        user = {
            'id': row[0],
            'first_name': row[1],
            'last_name': row[2],
            'middle_name': row[3],
            'phone': row[4],
            'email': row[5],
            'birthdate': row[6],
            'gender': row[7],
            'biography': row[8],
            'username': row[9],
            'languages': [lang for lang in row[10] if lang] if row[10] else []
        }

        return user
    except Exception as e:
        logger.error(f"Error getting user by ID: {str(e)}")
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def get_user_by_credentials(username: str, password: str) -> Optional[Dict]:
    conn = None
    cursor = None
    try:
        conn = create_connection()
        cursor = conn.cursor()

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        query = """
            SELECT id FROM Users 
            WHERE username = %s AND password_hash = %s
        """
        
        if not execute_safe(cursor, query, (username, password_hash)):
            return None

        row = cursor.fetchone()
        if not row:
            return None

        return get_user_by_id(row[0])
    except Exception as e:
        logger.error(f"Error authenticating user: {str(e)}")
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def update_user(user_id: int, user_data: Dict) -> bool:
    conn = None
    cursor = None
    try:
        conn = create_connection()
        cursor = conn.cursor()

        required_fields = ['first_name', 'last_name', 'phone', 'email',
                         'birthdate', 'gender', 'biography']
        if not all(field in user_data for field in required_fields):
            logger.error("Missing required fields in user data")
            return False

        update_query = """
            UPDATE Users
            SET first_name = %s,
                last_name = %s,
                middle_name = %s,
                phone = %s,
                email = %s,
                birthdate = %s,
                gender = %s,
                biography = %s
            WHERE id = %s
        """
        update_params = (
            user_data['first_name'][:50],
            user_data['last_name'][:50],
            user_data.get('middle_name', '')[:50],
            user_data['phone'][:20],
            user_data['email'][:100],
            user_data['birthdate'],
            user_data['gender'],
            user_data['biography'][:500],
            user_id
        )

        if not execute_safe(cursor, update_query, update_params):
            return False

        delete_query = "DELETE FROM UserProgrammingLanguages WHERE user_id = %s"
        if not execute_safe(cursor, delete_query, (user_id,)):
            conn.rollback()
            return False

        if 'languages' in user_data and user_data['languages']:
            for lang in user_data['languages']:
                insert_query = """
                    INSERT INTO UserProgrammingLanguages (user_id, language_id)
                    VALUES (%s, (SELECT id FROM ProgrammingLanguages WHERE name = %s))
                """
                if not execute_safe(cursor, insert_query, (user_id, str(lang)[:50])):
                    conn.rollback()
                    return False

        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        if conn:
            conn.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def init_db():
    conn = None
    cursor = None
    try:
        conn = create_connection()
        cursor = conn.cursor()

        execute_safe(cursor, """
            CREATE TABLE IF NOT EXISTS Users (
                id SERIAL PRIMARY KEY,
                first_name VARCHAR(50) NOT NULL,
                last_name VARCHAR(50) NOT NULL,
                middle_name VARCHAR(50),
                phone VARCHAR(20) NOT NULL,
                email VARCHAR(100) NOT NULL,
                birthdate DATE NOT NULL,
                gender VARCHAR(10) NOT NULL,
                biography TEXT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        execute_safe(cursor, """
            CREATE TABLE IF NOT EXISTS ProgrammingLanguages (
                id SERIAL PRIMARY KEY,
                name VARCHAR(50) UNIQUE NOT NULL
            )
        """)
        execute_safe(cursor, """
            CREATE TABLE IF NOT EXISTS UserProgrammingLanguages (
                user_id INTEGER REFERENCES Users(id),
                language_id INTEGER REFERENCES ProgrammingLanguages(id),
                PRIMARY KEY (user_id, language_id)
            )
        """)

        languages = ['Pascal', 'C', 'C++', 'JavaScript', 'PHP', 
                    'Python', 'Java', 'Haskel', 'Clojure', 'Prolog', 'Scala', 'Go']
        
        for lang in languages:
            execute_safe(cursor, """
                INSERT INTO ProgrammingLanguages (name)
                VALUES (%s)
                ON CONFLICT (name) DO NOTHING
            """, (lang,))

        conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        if conn:
            conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    # При запуске файла напрямую инициализируем базу данных
    init_db()
