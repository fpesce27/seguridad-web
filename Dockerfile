FROM python:3.9-slim

WORKDIR /app

# Copiar los archivos de requisitos primero para aprovechar la caché de Docker
COPY requirements.txt .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto de los archivos de la aplicación
COPY . .

# Crear directorio de logs
RUN mkdir -p logs

# Exponer el puerto que usa Flask
EXPOSE 5001

# Comando para ejecutar la aplicación
CMD ["python", "app.py"] 