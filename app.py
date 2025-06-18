from flask import Flask, request, jsonify, render_template, redirect, url_for
import jwt
import hashlib
import json
from datetime import datetime, timedelta
import os
import itertools
import string
import time
import re
import sqlite3

app = Flask(__name__)

# Vulnerabilidad 1: Broken Access Control
# El secreto JWT es débil y predecible
JWT_SECRET = "secret_key"  # Vulnerabilidad 1: Clave JWT hardcodeada

# Vulnerabilidad 4: Salt estático y débil
SALT = "salt"  # Vulnerabilidad 4: Salt estático

# Vulnerabilidad 5: Conexión a base de datos sin parámetros de configuración
def get_db():
    conn = sqlite3.connect('audit.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # Eliminar la base de datos si existe
    if os.path.exists('audit.db'):
        os.remove('audit.db')
    
    conn = get_db()
    c = conn.cursor()
    
    # Vulnerabilidad 5: Tabla sin índices ni restricciones
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            auditor TEXT,
            report TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Vulnerabilidad 5: Tabla de usuarios sin restricciones
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            role TEXT
        )
    ''')
    
    # Vulnerabilidad 5: Tabla de notas sin restricciones
    c.execute('''
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student TEXT,
            subject TEXT,
            grade INTEGER
        )
    ''')
    
    # Insertar usuarios iniciales con contraseñas en texto plano
    users_data = [
        ("admin", "admin", "admin"),
        ("monitor", "password", "monitor"),
        ("Juan", "password", "student"),
        ("auditor1", "password", "auditor")
    ]
    
    # Convertir contraseñas a hash MD5 con salt
    users = []
    for username, password, role in users_data:
        password_hash = hashlib.md5((password + SALT).encode()).hexdigest()
        users.append((username, password_hash, role))
        print(f"Usuario: {username}, Contraseña: {password}, Hash: {password_hash}")
    
    c.executemany('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', users)
    
    # Insertar notas iniciales
    grades_data = [
        ("Juan", "Análisis Matemático I", 2),
        ("Juan", "Algoritmos y Estructuras de Datos", 4),
        ("Juan", "Física I", 3),
        ("Juan", "Matemática Discreta", 1 )
    ]
    
    c.executemany('INSERT INTO grades (student, subject, grade) VALUES (?, ?, ?)', grades_data)
    
    conn.commit()
    conn.close()

# Inicializar la base de datos
init_db()



# Vulnerabilidad 3: Logging inseguro - Almacenamiento en memoria
app_logs = []

def add_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    app_logs.append({"timestamp": timestamp, "message": message})

def log_request():
    """Función para registrar detalles de la request"""
    method = request.method
    path = request.path
    ip = request.remote_addr
    
    # Obtener el usuario si hay un token
    username = "No autenticado"
    if 'Authorization' in request.headers:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload.get('username', 'Token inválido')
        except:
            username = "Token inválido"
    
    # Loggear la request de forma más simple
    add_log(f"{method} {path} - {username}")

# Middleware para loggear todas las requests
@app.before_request
def before_request():
    log_request()

def check_auth(required_roles):
    """Función para verificar la autenticación y el rol del usuario"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return None, "No token provided"
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if payload.get('role') not in required_roles:
            return None, "Acceso denegado"
        return payload, None
    except:
        return None, "Token inválido"
    
def check_auth_from_db(required_roles):
    """Función para verificar la autenticación y el rol del usuario desde la base de datos"""
    conn = get_db()
    c = conn.cursor()

    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return None, "No token provided"
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        username = payload.get('username')
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        
        if not user:
            return None, "Usuario no encontrado"
        
        if user['role'] not in required_roles:
            return None, "Acceso denegado"
        
        return dict(user), None
    except:
        return None, "Token inválido"
    finally:
        conn.close()
    
@app.errorhandler(404)
def page_not_found(e):
    return redirect('/')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Vulnerabilidad 4: SQL Injection en login
    conn = get_db()
    c = conn.cursor()
    password_hash = hashlib.md5((password + SALT).encode()).hexdigest()
    query = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
    c.execute(query, (username, password_hash))
    user = c.fetchone()
    conn.close()
    
    if user:
        token = jwt.encode({
            'username': username,
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, JWT_SECRET, algorithm='HS256')
        
        # Determinar la redirección según el rol
        redirect_url = "/dashboard"  # default
        if user['role'] == 'monitor':
            redirect_url = "/admin/logs-page"
        elif user['role'] == 'auditor':
            redirect_url = "/audit"
        elif user['role'] == 'admin':
            redirect_url = "/admin/logs-page"
        
        return jsonify({
            "message": "Login exitoso",
            "token": token,
            "role": user['role'],
            "redirect": redirect_url
        })
    
    add_log(f"Intento de login fallido: {username}")
    return jsonify({"error": "Credenciales inválidas"}), 401

@app.route('/change-password', methods=['GET'])
def change_password_template():
    return render_template('change_password.html')

@app.route('/change-password', methods=['POST'])
def change_password():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    new_password = data.get('new_password')

    conn = get_db()
    c = conn.cursor()
    password_hash = hashlib.md5((password + SALT).encode()).hexdigest()
    query = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
    c.execute(query, (username, password_hash))
    user = c.fetchone()

    if not user:
        add_log(f"Intento de cambio de contraseña fallido: {username}")
        conn.close()
        return jsonify({"error": "Credenciales inválidas"}), 401

    password_hash = hashlib.md5((new_password + SALT).encode()).hexdigest()
    query = "UPDATE users SET password_hash = ? WHERE username = ?"
    c.execute(query, (password_hash, username))
    conn.commit()
    conn.close()
    add_log(f"Cambio de contraseña: {username} - nuevo hash de contraseña: {password_hash}")
    return jsonify({"message": "Contraseña cambiada exitosamente"})
    

@app.route('/grades', methods=['GET'])
def get_grades():
    payload, error = check_auth_from_db(['student'])
    if error:
        return jsonify({"error": error}), 401
    
    username = payload.get('username')
    if payload.get('role') == 'student':
        # Vulnerabilidad 5: SQL Injection en consulta de notas
        conn = get_db()
        c = conn.cursor()
        query = "SELECT subject, grade FROM grades WHERE student = ?"
        c.execute(query, (username,))
        grades = {row['subject']: row['grade'] for row in c.fetchall()}
        conn.close()
        
        add_log(f"Acceso a notas: {username}")
        return jsonify({"grades": grades})
    return jsonify({"error": "Acceso denegado"}), 403

@app.route('/grades', methods=['POST'])
def update_grades():
    payload, error = check_auth_from_db(['admin'])
    if error:
        return jsonify({"error": error}), 401
    
    data = request.get_json()
    subject = data.get('subject')
    grade = data.get('grade')
    username = payload.get('username')
    
    # Vulnerabilidad 5: SQL Injection en actualización de notas
    conn = get_db()
    c = conn.cursor()
    query = f"UPDATE grades SET grade = {grade} WHERE student = '{username}' AND subject = '{subject}'"
    c.execute(query)
    conn.commit()
    conn.close()
    
    add_log(f"Actualización de nota: {username} - {subject} = {grade}")
    return jsonify({"message": "Nota actualizada exitosamente"})

@app.route('/admin/logs', methods=['GET'])
def get_logs():
    payload, error = check_auth(['admin', 'monitor'])
    if error:
        return jsonify({"error": error}), 401
    
    add_log(f"Acceso a logs: {payload.get('username')}")
    return jsonify({"logs": app_logs})

@app.route('/admin/logs-page')
def logs_page():
    payload, error = check_auth(['admin', 'monitor'])
    if error:
        return redirect('/')
    
    add_log(f"Acceso a página de logs: {payload.get('username')}")
    return render_template('logs.html')

@app.route('/changeJwtRole', methods=['POST'])
def change_jwt_role():
    payload, error = check_auth(['admin', 'student', 'monitor', 'auditor'])
    if error:
        return jsonify({"error": error}), 401
    
    new_role = request.json.get('role')
    old_role = payload.get('role')
    payload['role'] = new_role
    
    # Vulnerabilidad 1: Token JWT inseguro
    new_token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    
    add_log(f"Cambio de rol: {payload.get('username')} ({old_role} -> {new_role})")
    return jsonify({"token": new_token})

@app.route('/crack-hash', methods=['POST'])
def crack_hash():
    data = request.get_json()
    target_hash = data.get('hash')
    
    # Lista de contraseñas comunes
    common_passwords = [
        "admin", "password", "123456", "qwerty",
        "monitor", "student1", "auditor1"  # Contraseñas reales del sistema
    ]
    
    # Intentar con contraseñas comunes
    for password in common_passwords:
        if hashlib.md5((password + SALT).encode()).hexdigest() == target_hash:
            return jsonify({
                "found": True,
                "password": password,
                "method": "common_password",
                "salt": SALT
            })
    
    # Si no se encuentra, intentar fuerza bruta
    for i in range(1000):
        test_password = str(i).zfill(4)
        if hashlib.md5((test_password + SALT).encode()).hexdigest() == target_hash:
            return jsonify({
                "found": True,
                "password": test_password,
                "method": "brute_force",
                "salt": SALT
            })
    
    return jsonify({"found": False})

@app.route('/audit')
def audit_page():
    payload, error = check_auth_from_db(['auditor'])
    if error:
        return redirect('/')
    add_log(f"Acceso a página de auditoría: {payload.get('username')}")
    return render_template('audit.html')

@app.route('/audit', methods=['POST'])
def submit_audit():
    payload, error = check_auth_from_db(['auditor'])
    if error:
        return jsonify({"error": error}), 401
    
    data = request.get_json()
    report = data.get('report')
    
    # Vulnerabilidad 5: SQL Injection en inserción de reportes
    conn = get_db()
    c = conn.cursor()
    query = f"INSERT INTO audit_reports (auditor, report) VALUES ('{payload['username']}', '{report}')"
    c.executescript(query)  # Cambiado de execute() a executescript() para permitir múltiples statements
    conn.commit()
    conn.close()
    
    add_log(f"Reporte de auditoría enviado: {payload['username']}")
    return jsonify({"message": "Reporte enviado exitosamente"})

@app.route('/api/audit-reports', methods=['GET'])
def get_audit_reports():
    payload, error = check_auth_from_db(['auditor'])
    if error:
        return jsonify({"error": error}), 401
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM audit_reports ORDER BY timestamp DESC')
    reports = [dict(row) for row in c.fetchall()]
    conn.close()
    
    add_log(f"Consulta de reportes de auditoría: {payload.get('username')}")
    return jsonify({"reports": reports})

if __name__ == '__main__':
    # Asegurarse de que el directorio de logs existe
    os.makedirs('logs', exist_ok=True)
    # Modificado para funcionar en Docker
    app.run(host='0.0.0.0', port=5001, debug=True) 