FROM python:3.11-slim

# Install exiftool dan dependencies sistem
RUN apt-get update && apt-get install -y \
    exiftool \
    libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies langsung
RUN pip install --no-cache-dir Flask==3.0.0 Werkzeug==3.0.1

# Copy aplikasi
COPY . .

# Buat folder uploads
RUN mkdir -p uploads

# Expose port
EXPOSE 8083

# Set environment variables
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# Run aplikasi
CMD ["python", "app.py"]