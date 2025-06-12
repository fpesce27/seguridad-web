from flask import Flask, request, jsonify, render_template
import jwt
import hashlib
import json
from datetime import datetime
import os
import itertools
import string
import time
import re

app = Flask(__name__)

# Vulnerabilidad 1: Broken Access Control
# El secreto JWT es débil y predecible
JWT_SECRET = "secret_key_123"  # En producción, esto debería ser una clave fuerte y secreta

# Base de datos simulada de usuarios
users_db = {
    "admin": {
        "password_hash": hashlib.md5("admin123".encode()).hexdigest(),  # Vulnerabilidad 4: Uso de MD5
        "role": "admin"
    },
    "user1": {
        "password_hash": hashlib.md5("password123".encode()).hexdigest(),
        "role": "user"
    }
}

# Vulnerabilidad 2: Insecure Design
# El endpoint de logs solo verifica el rol en el token, sin autenticación adicional
@app.route('/admin/logs', methods=['GET'])
def get_logs():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        # Vulnerabilidad 1: No se verifica la firma del token
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if payload.get('role') == 'admin':
            with open('logs/app.log', 'r') as f:
                logs = f.readlines()
            return jsonify({"logs": logs})
        return jsonify({"error": "Acceso denegado"}), 403
    except:
        return jsonify({"error": "Token inválido"}), 401

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username in users_db:
        # Vulnerabilidad 4: Uso de MD5 para hashing de contraseñas
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        if password_hash == users_db[username]['password_hash']:
            # Vulnerabilidad 1: Token JWT inseguro
            token = jwt.encode({
                'username': username,
                'role': users_db[username]['role']
            }, JWT_SECRET, algorithm='HS256')
            
            # Vulnerabilidad 3: Logging inseguro de credenciales
            log_entry = f"{datetime.now()} - Login exitoso - Usuario: {username}, Password Hash: {password_hash}\n"
            with open('logs/app.log', 'a') as f:
                f.write(log_entry)
            
            return jsonify({"token": token})
        else:
            # Vulnerabilidad 3: Logging inseguro de intentos fallidos
            log_entry = f"{datetime.now()} - Login fallido - Usuario: {username}, Password Hash: {password_hash}\n"
            with open('logs/app.log', 'a') as f:
                f.write(log_entry)
    
    return jsonify({"error": "Credenciales inválidas"}), 401

@app.route('/')
def home():
    return render_template('index.html')







# ENDPOINTS PARA PROBAR VULNERABILIDADES
@app.route('/changeJwtRole', methods=['POST'])
def change_jwt_role():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    new_role = request.json.get('role')
    
    try:
        # Vulnerabilidad 1: No se verifica la firma del token
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        payload['role'] = new_role
        
        # Vulnerabilidad 1: Token JWT inseguro
        new_token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        
        return jsonify({"token": new_token})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

@app.route('/crack-hash', methods=['POST'])
def crack_hash():
    data = request.get_json()
    hash_target = data.get('hash')
    
    if not hash_target:
        return jsonify({"error": "Se requiere un hash MD5"}), 400
    
    # Verificar que el hash tiene el formato correcto de MD5
    if not re.match(r'^[a-f0-9]{32}$', hash_target):
        return jsonify({"error": "Hash MD5 inválido"}), 400
    
    # Intentar primero con contraseñas comunes
    common_passwords = [
        "password123", "admin123", "123456", "qwerty", 
        "letmein", "welcome", "monkey", "dragon"
    ]
    
    for password in common_passwords:
        if hashlib.md5(password.encode()).hexdigest() == hash_target:
            return jsonify({
                "success": True,
                "password": password,
                "method": "common_password"
            })
    
    # Si no se encuentra en la lista común, intentar con fuerza bruta
    chars = string.ascii_lowercase + string.digits
    max_length = 6  # Limitamos a 6 caracteres para no sobrecargar el servidor
    
    start_time = time.time()
    for length in range(1, max_length + 1):
        for guess in itertools.product(chars, repeat=length):
            guess = ''.join(guess)
            if hashlib.md5(guess.encode()).hexdigest() == hash_target:
                end_time = time.time()
                return jsonify({
                    "success": True,
                    "password": guess,
                    "method": "brute_force",
                    "time_taken": f"{end_time - start_time:.2f} segundos"
                })
    
    return jsonify({
        "success": False,
        "message": "No se pudo encontrar la contraseña",
        "time_taken": f"{time.time() - start_time:.2f} segundos"
    })

if __name__ == '__main__':
    # Asegurarse de que el directorio de logs existe
    os.makedirs('logs', exist_ok=True)
    # Modificado para funcionar en Docker
    app.run(host='0.0.0.0', port=5001, debug=True) 