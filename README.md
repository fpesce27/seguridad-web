# Sistema Escolar Vulnerable
![image](https://github.com/user-attachments/assets/098e5a33-86c9-4ae6-a9d6-6210e57b959c)

Este es un sistema escolar intencionalmente vulnerable diseñado para demostrar cómo una cadena de vulnerabilidades puede permitir a un estudiante modificar sus notas. El sistema implementa varias vulnerabilidades del OWASP Top 10 que pueden ser explotadas secuencialmente.

## Escenario

En este sistema, tanto alumnos como profesores tienen sus respectivos usuarios. El objetivo es demostrar cómo, partiendo de un usuario con rol de alumno, se puede llegar a cambiar las notas de todos los exámenes a través de una cadena de vulnerabilidades.

## Cadena de Vulnerabilidades

### 1. A02:2021 – Cryptographic Failures
- **Vulnerabilidad**: JWT con algoritmo débil (HS256) y secret key predecible
- **Explotación**: 
  - El token JWT puede ser decodificado y modificado
  - La secret key puede ser obtenida mediante fuerza bruta
  - Permite modificar el rol en el token

### 2. A04:2021 – Insecure Design
- **Vulnerabilidad**: Validación de roles basada en el token JWT
- **Explotación**:
  - Modificación del rol en el token decodificado
  - Acceso a endpoints restringidos
  - Obtención de acceso a logs del sistema

### 3. A09:2021 – Security Logging and Monitoring Failures
- **Vulnerabilidad**: Logs que contienen información sensible
- **Explotación**:
  - Los logs contienen hashes de contraseñas
  - Exposición de credenciales de usuarios con privilegios
  - Permite obtener credenciales de auditor

### 4. A02:2021 – Cryptographic Failures (Contraseñas)
- **Vulnerabilidad**: Uso de MD5 con salt estático
- **Explotación**:
  - El salt es predecible y compartido
  - Permite revertir hashes de contraseñas
  - Obtención de credenciales de auditor

### 5. A03:2021 – Injection
- **Vulnerabilidad**: SQL Injection en formulario de auditoría
- **Explotación**:
  - Modificación de notas en la base de datos
  - Ejemplo de payload:
  ```sql
  '); UPDATE grades SET grade = 10 WHERE student = 'Juan'; --
  ```

## Cómo Ejecutar

### Opción 1: Instalación Local
1. Instalar dependencias:
```bash
pip install -r requirements.txt
```

2. Ejecutar la aplicación:
```bash
python app.py
```

### Opción 2: Usando Docker
1. Construir la imagen:
```bash
docker build -t vulnerable-app .
```

2. Ejecutar el contenedor:
```bash
docker run -p 5001:5001 vulnerable-app
```

3. Acceder a http://localhost:5001

## Credenciales de Prueba

- Admin: admin/admin
- Monitor: monitor/password
- Estudiante: Juan/password
- Auditor: auditor1/password

## Estructura de la Base de Datos

### Tabla users
- username (TEXT)
- password_hash (TEXT)
- role (TEXT)

### Tabla grades
- id (INTEGER)
- student (TEXT)
- subject (TEXT)
- grade (INTEGER)

### Tabla audit_reports
- id (INTEGER)
- auditor (TEXT)
- report (TEXT)
- timestamp (DATETIME)

## Ejemplos de Explotación

### 1. Obtención de Secret Key JWT
```bash
# Usar herramientas como jwt_tool o hashcat para fuerza bruta
jwt_tool <token> -C -d wordlist.txt
```

### 2. Modificación de Rol en JWT
```javascript
// Decodificar token
const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...";
const decoded = JSON.parse(atob(token.split('.')[1]));
// Modificar rol
decoded.role = "auditor";
```

### 3. SQL Injection en Auditoría
```sql
'); UPDATE grades SET grade = 10 WHERE student = 'Juan'; --
```

## Notas de Seguridad

⚠️ **ADVERTENCIA**: Este sistema es intencionalmente vulnerable y NO debe ser utilizado en un entorno de producción. Está diseñado únicamente para fines educativos y de práctica de seguridad.

## Mejores Prácticas que NO se Implementan

1. Uso de consultas parametrizadas
2. Almacenamiento seguro de contraseñas (bcrypt, Argon2)
3. Tokens JWT seguros con expiración
4. Logging seguro sin información sensible
5. Validación de entrada
6. Protección contra CSRF
7. Headers de seguridad
8. Rate limiting
9. Sanitización de datos
10. Control de acceso basado en roles (RBAC) seguro 
