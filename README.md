# Aplicación Web Vulnerable - TP Seguridad

Esta es una aplicación web intencionalmente vulnerable para fines educativos, diseñada para demostrar cómo las vulnerabilidades pueden encadenarse para comprometer un sistema completo.

## Vulnerabilidades Implementadas

### 1. Broken Access Control (A01:2021)
- El token JWT contiene el rol del usuario y puede ser modificado manualmente
- El servidor no valida correctamente la firma del token
- Clave secreta JWT débil y predecible

### 2. Insecure Design (A04:2021)
- Endpoint `/admin/logs` protegido solo por el rol en el token
- No requiere autenticación adicional.
- Permite acceso a logs sensibles con solo modificar el token

### 3. Security Logging and Monitoring Failures (A09:2021)
- Los logs contienen información sensible (hashes de contraseñas)
- No hay rotación de logs
- Los logs son accesibles sin autenticación adecuada

### 4. Cryptographic Failures (A02:2021)
- Uso de MD5 para hashing de contraseñas
- Algoritmo débil y vulnerable a ataques de fuerza bruta
- No se utiliza salt en el hashing

## Cadena de Explotación

1. El atacante intercepta un token JWT de un usuario normal
2. Modifica el rol en el token a "admin"
3. Accede al endpoint `/admin/logs` con el token modificado
4. Obtiene hashes de contraseñas de los logs
5. Utiliza herramientas de cracking para obtener las contraseñas en texto plano
6. Accede a cuentas reales con las credenciales obtenidas

## Instalación y Ejecución

### Opción 1: Instalación Local

1. Instalar dependencias:
```bash
pip install -r requirements.txt
```

2. Ejecutar la aplicación:
```bash
python app.py
```

3. Acceder a http://localhost:5001

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

- Usuario normal:
  - Username: user1
  - Password: password123

- Administrador:
  - Username: admin
  - Password: admin123

## Advertencia

Esta aplicación es intencionalmente vulnerable y debe usarse SOLO en un entorno controlado para fines educativos. No debe desplegarse en producción ni en entornos accesibles públicamente. 