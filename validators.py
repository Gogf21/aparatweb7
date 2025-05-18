import re
from datetime import datetime
from html import escape
from typing import Optional, Dict, List

def sanitize_input(input_str: str, max_length: int = 255) -> str:
   
    if not input_str:
        return ""
    
   
    sanitized = re.sub(r'[<>"\'\`;\\/]', '', str(input_str).strip())
    
   
    return sanitized[:max_length]

def validate_fullname(fullname: str) -> Optional[str]:
    fullname = sanitize_input(fullname, 100)
    if not fullname:
        return "ФИО обязательно для заполнения"
    parts = fullname.split()
    if len(parts) < 2:
        return "Введите имя и фамилию"
    if not all(re.match(r'^[a-zA-Zа-яА-ЯёЁ\-]+$', part) for part in parts):
        return "ФИО должно содержать только буквы и дефисы"
    return None

def validate_phone(phone: str) -> Optional[str]:
    phone = sanitize_input(phone, 20)
    if not phone:
        return "Телефон обязателен для заполнения"
    if not re.match(r'^\+?[0-9\s\-\(\)]{10,15}$', phone):
        return "Неверный формат телефона"
    return None

def validate_email(email: str) -> Optional[str]:
    email = sanitize_input(email, 100)
    if not email:
        return "Email обязателен для заполнения"
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return "Некорректный email"
    return None

def validate_birthdate(birthdate: str) -> Optional[str]:
    if not birthdate:
        return "Дата рождения обязательна"
    try:
        date = datetime.strptime(birthdate, '%Y-%m-%d')
        if date > datetime.now():
            return "Дата рождения не может быть в будущем"
        if (datetime.now() - date).days > 365 * 150:
            return "Некорректная дата рождения"
    except ValueError:
        return "Неверный формат даты"
    return None

def validate_gender(gender: str) -> Optional[str]:
    if gender not in ['male', 'female']:
        return "Выберите пол"
    return None

def validate_languages(languages: List[str]) -> Optional[str]:
    valid_langs = {'Pascal', 'C', 'C++', 'JavaScript', 'PHP', 
                  'Python', 'Java', 'Haskel', 'Clojure', 'Prolog', 'Scala', 'Go'}
    if not languages:
        return "Выберите хотя бы один язык"
    if not all(lang in valid_langs for lang in languages):
        return "Выбраны недопустимые языки"
    if len(languages) > 5:
        return "Выберите не более 5 языков"
    return None

def validate_biography(bio: str) -> Optional[str]:
    bio = sanitize_input(bio, 1000)
    if not bio or len(bio.strip()) < 10:
        return "Биография должна содержать минимум 10 символов"
    return None

def validate_contract(contract: str) -> Optional[str]:
    if contract != 'on':
        return "Необходимо подтвердить контракт"
    return None

def validate_form_data(data: Dict) -> Dict[str, str]:
   
    errors = {}
    
   
    if error := validate_fullname(data.get('fullname', [''])[0]):
        errors['fullname'] = error
    
    if error := validate_phone(data.get('phone', [''])[0]):
        errors['phone'] = error
    
    if error := validate_email(data.get('email', [''])[0]):
        errors['email'] = error
    
    if error := validate_birthdate(data.get('birthdate', [''])[0]):
        errors['birthdate'] = error
    
    if error := validate_gender(data.get('gender', [''])[0]):
        errors['gender'] = error
    
    if error := validate_languages(data.get('language', [])):
        errors['language'] = error
    
    if error := validate_biography(data.get('bio', [''])[0]):
        errors['bio'] = error
    
    if error := validate_contract(data.get('contract', [''])[0]):
        errors['contract'] = error
    
    return errors

def validate_login_form(data: Dict) -> Dict[str, str]:
    errors = {}
    
    if not data.get('username', [''])[0]:
        errors['username'] = "Логин обязателен"
    elif len(data['username'][0]) > 50:
        errors['username'] = "Логин слишком длинный"
    
    if not data.get('password', [''])[0]:
        errors['password'] = "Пароль обязателен"
    elif len(data['password'][0]) > 100:
        errors['password'] = "Пароль слишком длинный"
    
    return errors
