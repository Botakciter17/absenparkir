# ---------- base ----------
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install runtime deps for Pillow & exiftool
RUN apt-get update && apt-get install -y --no-install-recommends \
    exiftool \
    libjpeg62-turbo \
    zlib1g \
    libtiff6 \
    libwebp7 \
    libopenjp2-7 \
    && rm -rf /var/lib/apt/lists/*

# ---------- app ----------
WORKDIR /app

# Install Python deps first (better layer caching)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the rest of the app
COPY . /app

# Ensure folders exist
RUN mkdir -p /app/uploads

# Create unprivileged user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8083

# Use gunicorn for production serving
# - 3 workers, each 8 threads, bind 0.0.0.0:8083
CMD ["gunicorn", "-w", "3", "-k", "gthread", "--threads", "8", "-b", "0.0.0.0:8083", "app:app"]
