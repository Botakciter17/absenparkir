from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
import os
import sqlite3
import subprocess
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2
import re
import pathlib
import hashlib
import secrets
from functools import wraps
from werkzeug.utils import secure_filename
import bleach
import requests
from threading import Thread
import json
from PIL import Image

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set True jika pakai HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB

BASE_DIR = pathlib.Path(__file__).parent
UPLOAD_FOLDER = str(BASE_DIR / "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DATABASE = str(BASE_DIR / "database.db")
LAST_CLEANUP_FILE = str(BASE_DIR / "last_cleanup.txt")
BACKUP_API_URL = "https://file.webbarya.my.id/files/upload/"
BACKUP_LOGIN_URL = "https://file.webbarya.my.id/files/login"
BACKUP_USERNAME = "bagus"
BACKUP_PASSWORD = "200817"

# ====== Config ======
TARGET_LAT = -6.741702
TARGET_LON = 111.036899
RADIUS_METERS = 50
MAX_UPLOAD_PER_DAY = 3
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIMEOUT = 300  # 5 menit

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'}
MAX_FILE_SIZE = 10 * 1024 * 1024

# Jadwal piket
JADWAL = {
    "Senin": [
        "Zifanna Hermin Najwa","Iin Nur Cahaya","Tiara Citra Kirana",
        "Alvianino Miftahul Arifin","Laili Ulin Nuha","Safa Arifatul Funun","Rafael Mahar Dhika"
    ],
    "Selasa": [
        "Inez Lu'luuil Makhnuun","Arifian Armansyah","Kamila Sunnatin Udiah",
        "Deby Maulina Shaputri","Kasih Syairawati","Eka Putriana","Ilma Imroatul Mufidah"
    ],
    "Rabu": [
        "Rio Eka Haryono Putra","Junian Satrio S","Bayu Aji Kuncoro",
        "Rehan Bayu Saefulloh","Ferica Agustine","KOKO Prasetyo"
    ],
    "Kamis": [
        "Arina Putri Octa Fajriya","Al Safa Puan Pujianto","Muhammad Khoirur Roziqin",
        "Aguntur Rizqiwanto Putra","Mukhamad Jazuli","Nutfasyavior Bahtera Sailla"
    ],
    "Jumat": [
        "Zahra Riyana","Refan Pramudiya","Sifa Naja Kamalul Mazaya",
        "Muhammad Faza Taftazani","Nasyifa Annafidza","Fadlila Cemelia Afrihani",
        "Arga Narwastu Deananta","Ananda Dandy Rizky Echa"
    ],
    "Sabtu": [
        "Alfia Nurul Ikamah","Selvi Kurniandri","Ema Selvina",
        "Raeesa Farras Fisabilillah","Raya Privea De Hollyhoney"
    ]
}

# Rate limiting storage (simple in-memory)
login_attempts = {}

# ====== Security Helpers ======
def hash_password(password):
    """Hash password dengan SHA256 + salt"""
    salt = "piket_sekolah_2024"  # Ganti dengan salt random untuk production
    return hashlib.sha256((password + salt).encode()).hexdigest()

def check_rate_limit(ip_address):
    """Check if IP is rate limited"""
    now = datetime.now()
    if ip_address in login_attempts:
        attempts, last_attempt = login_attempts[ip_address]
        if (now - last_attempt).seconds < LOGIN_TIMEOUT and attempts >= MAX_LOGIN_ATTEMPTS:
            return False
        if (now - last_attempt).seconds > LOGIN_TIMEOUT:
            login_attempts[ip_address] = (0, now)
    return True

def record_failed_login(ip_address):
    """Record failed login attempt"""
    now = datetime.now()
    if ip_address in login_attempts:
        attempts, _ = login_attempts[ip_address]
        login_attempts[ip_address] = (attempts + 1, now)
    else:
        login_attempts[ip_address] = (1, now)

def reset_login_attempts(ip_address):
    """Reset login attempts after successful login"""
    if ip_address in login_attempts:
        del login_attempts[ip_address]

def sanitize_input(text):
    """Sanitize user input to prevent XSS"""
    if not text:
        return ""
    return bleach.clean(str(text).strip())

def upload_to_backup_api(file_path, filename):
    """Upload file to backup API with login"""
    session_api = requests.Session()
    
    try:
        # Step 1: Login to get session/token
        login_data = {
            'username': BACKUP_USERNAME,
            'password': BACKUP_PASSWORD
        }
        
        login_response = session_api.post(BACKUP_LOGIN_URL, data=login_data, timeout=15)
        
        if login_response.status_code != 200:
            return False, f"Login failed: HTTP {login_response.status_code}"
        
        # Check if login successful
        if 'login' in login_response.url.lower() or 'error' in login_response.text.lower():
            return False, "Login credentials rejected"
        
        # Step 2: Upload file using authenticated session
        with open(file_path, 'rb') as f:
            files = {'file': (filename, f, 'image/jpeg')}
            upload_response = session_api.post(BACKUP_API_URL, files=files, timeout=30)
            
            if upload_response.status_code == 200:
                return True, "Success"
            else:
                return False, f"Upload failed: HTTP {upload_response.status_code}"
                
    except requests.exceptions.Timeout:
        return False, "Timeout"
    except requests.exceptions.RequestException as e:
        return False, str(e)[:100]
    except Exception as e:
        return False, str(e)[:100]
    finally:
        session_api.close()

def get_last_cleanup_date():
    """Get last cleanup date from file"""
    try:
        if os.path.exists(LAST_CLEANUP_FILE):
            with open(LAST_CLEANUP_FILE, 'r') as f:
                return f.read().strip()
    except:
        pass
    return None

def set_last_cleanup_date(date_str):
    """Save last cleanup date to file"""
    try:
        with open(LAST_CLEANUP_FILE, 'w') as f:
            f.write(date_str)
    except:
        pass

def cleanup_old_photos_async():
    """Cleanup old photos in background thread"""
    def do_cleanup():
        try:
            today = datetime.now().strftime("%Y-%m-%d")
            last_cleanup = get_last_cleanup_date()
            
            # Skip if already cleaned today
            if last_cleanup == today:
                return
            
            conn = get_db_conn()
            c = conn.cursor()
            
            # Get yesterday's photos
            yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
            c.execute("SELECT id, filename, tanggal FROM absensi WHERE tanggal < ?", (today,))
            old_records = c.fetchall()
            
            success_count = 0
            fail_count = 0
            
            for record in old_records:
                file_path = os.path.join(UPLOAD_FOLDER, record['filename'])
                
                # Upload to backup if file exists
                if os.path.exists(file_path):
                    success, message = upload_to_backup_api(file_path, record['filename'])
                    if success:
                        success_count += 1
                        # Delete file after successful upload
                        try:
                            os.remove(file_path)
                        except:
                            pass
                    else:
                        fail_count += 1
                        print(f"Failed to upload {record['filename']}: {message}")
                
                # Delete database record
                c.execute("DELETE FROM absensi WHERE id=?", (record['id'],))
            
            conn.commit()
            conn.close()
            
            # Mark cleanup as done
            set_last_cleanup_date(today)
            
            print(f"Cleanup complete: {success_count} uploaded, {fail_count} failed, {len(old_records)} records deleted")
            
        except Exception as e:
            print(f"Cleanup error: {e}")
    
    # Run cleanup in background thread
    thread = Thread(target=do_cleanup)
    thread.daemon = True
    thread.start()

def login_required(f):
    """Decorator untuk proteksi route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Silakan login terlebih dahulu", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator untuk admin only"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash("Akses ditolak: Admin only", "danger")
            return redirect(url_for('upload'))
        return f(*args, **kwargs)
    return decorated_function

# ====== Database Helpers ======
def get_db_conn():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(file_path):
    """Validate if file is actually an image using Pillow"""
    try:
        with Image.open(file_path) as img:
            # Verify it's a valid image
            img.verify()
        
        # Check file size
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            return False
        
        # Check if format is allowed
        with Image.open(file_path) as img:
            if img.format.lower() not in ['jpeg', 'png', 'gif', 'bmp', 'webp']:
                return False
        
        return True
    except Exception as e:
        return False

def count_today_uploads(user_id):
    """Count uploads today"""
    conn = get_db_conn()
    c = conn.cursor()
    today = datetime.now().strftime("%Y-%m-%d")
    c.execute("SELECT COUNT(*) as count FROM absensi WHERE user_id=? AND tanggal=?", (user_id, today))
    result = c.fetchone()
    conn.close()
    return result['count'] if result else 0

def haversine_meters(lat1, lon1, lat2, lon2):
    R = 6371000.0
    phi1 = radians(lat1)
    phi2 = radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)
    a = sin(dphi/2)**2 + cos(phi1)*cos(phi2)*sin(dlambda/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

def make_username(name):
    first = name.strip().split()[0]
    uname = re.sub(r'[^a-zA-Z0-9]', '', first).lower()
    if not uname:
        uname = re.sub(r'[^a-zA-Z0-9]', '', name).lower()[:8]
    return uname

def ensure_db():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nama TEXT NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'petugas' CHECK(role IN ('admin', 'petugas'))
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS absensi (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    tanggal TEXT NOT NULL,
                    datetime_exif TEXT,
                    latitude REAL,
                    longitude REAL,
                    status TEXT CHECK(status IN ('Pending', 'Disetujui', 'Ditolak')),
                    alasan TEXT,
                    exif_text TEXT,
                    jenis TEXT DEFAULT 'hadir' CHECK(jenis IN ('hadir', 'izin')),
                    keterangan_izin TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                 )''')
    # Create indices for better performance
    c.execute('''CREATE INDEX IF NOT EXISTS idx_absensi_user_tanggal 
                 ON absensi(user_id, tanggal)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_absensi_status 
                 ON absensi(status)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_absensi_jenis 
                 ON absensi(jenis)''')
    conn.commit()
    conn.close()

def seed_users_from_jadwal():
    conn = get_db_conn()
    c = conn.cursor()
    for day, names in JADWAL.items():
        for full in names:
            username = make_username(full)
            password_hash = hash_password(username)
            c.execute("SELECT id FROM users WHERE username=?", (username,))
            if c.fetchone():
                c.execute("UPDATE users SET nama=?, password=?, role='petugas' WHERE username=?", 
                         (full, password_hash, username))
            else:
                c.execute("INSERT INTO users (nama, username, password, role) VALUES (?,?,?,?)", 
                         (full, username, password_hash, 'petugas'))
    # Ensure admin with hashed password
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (nama, username, password, role) VALUES (?,?,?,?)", 
                 ('Admin','admin', hash_password('admin'),'admin'))
    conn.commit()
    conn.close()

def run_exiftool_on_file(path):
    try:
        # Sanitize path to prevent command injection
        if not os.path.exists(path):
            return "File not found"
        p = subprocess.run(['exiftool', path], capture_output=True, text=True, timeout=6)
        return p.stdout or ""
    except subprocess.TimeoutExpired:
        return "ExifTool timeout"
    except Exception as e:
        return f"ExifTool error: {str(e)[:100]}"  # Limit error message length

def parse_exif_datetime(exif_text):
    m = re.search(r'(\d{4}[:\-]\d{2}[:\-]\d{2})[ T](\d{2}):(\d{2})', exif_text)
    if m:
        date_part = m.group(1).replace('-', ':')
        hour = int(m.group(2))
        minute = int(m.group(3))
        return date_part, hour, minute
    return None, None, None

def parse_exif_gps(exif_text):
    lat = None
    lon = None
    for line in exif_text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        val = val.strip()
        if "GPS Latitude" in key:
            try:
                lat = float(val.split()[0])
            except:
                m = re.search(r'(\d+)\s*deg\s*(\d+)\'\s*([\d.]+)"\s*([NS])', val)
                if m:
                    d, m_, s, ref = m.groups()
                    lat = int(d) + int(m_) / 60 + float(s) / 3600
                    if ref.upper() == 'S':
                        lat = -lat
        if "GPS Longitude" in key:
            try:
                lon = float(val.split()[0])
            except:
                m = re.search(r'(\d+)\s*deg\s*(\d+)\'\s*([\d.]+)"\s*([EW])', val)
                if m:
                    d, m_, s, ref = m.groups()
                    lon = int(d) + int(m_) / 60 + float(s) / 3600
                    if ref.upper() == 'W':
                        lon = -lon
    return lat, lon

# ====== Init DB & seed ======
ensure_db()
seed_users_from_jadwal()

# Run cleanup on startup
cleanup_old_photos_async()

# ====== Security Headers Middleware ======
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self'"
    return response

# ====== Routes ======
@app.route('/', methods=['GET','POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard' if session.get('role')=='admin' else 'upload'))
    
    if request.method == 'POST':
        ip_address = request.remote_addr
        
        # Check rate limiting
        if not check_rate_limit(ip_address):
            remaining_time = LOGIN_TIMEOUT // 60
            flash(f"Terlalu banyak percobaan login. Coba lagi dalam {remaining_time} menit.", "danger")
            return render_template('login.html', jadwal=JADWAL)
        
        username = sanitize_input(request.form.get('username', '')).lower()
        password = sanitize_input(request.form.get('password', ''))
        
        # Validate input
        if not username or not password:
            flash("Username dan password harus diisi", "warning")
            return render_template('login.html', jadwal=JADWAL)
        
        if len(username) > 50 or len(password) > 100:
            flash("Input terlalu panjang", "danger")
            return render_template('login.html', jadwal=JADWAL)
        
        conn = get_db_conn()
        c = conn.cursor()
        password_hash = hash_password(password)
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password_hash))
        user = c.fetchone()
        conn.close()
        
        if user:
            reset_login_attempts(ip_address)
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nama'] = user['nama']
            session['role'] = user['role']
            session['csrf_token'] = secrets.token_hex(16)
            
            flash(f"Selamat datang, {user['nama']}!", "success")
            return redirect(url_for('dashboard' if user['role']=='admin' else 'upload'))
        else:
            record_failed_login(ip_address)
            attempts_left = MAX_LOGIN_ATTEMPTS - login_attempts.get(ip_address, (0, None))[0]
            flash(f"Login gagal! Sisa percobaan: {attempts_left}", "danger")
    
    return render_template('login.html', jadwal=JADWAL)

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    # Check for cleanup on every request
    cleanup_old_photos_async()
    
    if request.method == 'POST':
        # CSRF protection (simple)
        if not session.get('csrf_token'):
            flash("Session expired. Please login again.", "danger")
            return redirect(url_for('login'))
        
        # Check upload limit
        upload_count = count_today_uploads(session['user_id'])
        if upload_count >= MAX_UPLOAD_PER_DAY:
            flash(f"Maksimal {MAX_UPLOAD_PER_DAY} kali upload per hari.", "danger")
            return redirect(request.url)
        
        f = request.files.get('file')
        if not f or f.filename == '':
            flash("Pilih file dulu.", "warning")
            return redirect(request.url)
        
        # Validate file extension
        if not allowed_file(f.filename):
            flash("File harus berupa gambar (jpg, jpeg, png, gif, bmp, webp).", "danger")
            return redirect(request.url)
        
        # Secure filename
        original_filename = secure_filename(f.filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_string = secrets.token_hex(4)
        filename = f"{timestamp}_{random_string}_{original_filename}"
        path = os.path.join(UPLOAD_FOLDER, filename)
        
        try:
            f.save(path)
        except Exception as e:
            flash("Gagal menyimpan file.", "danger")
            return redirect(request.url)
        
        # Validate image content
        if not validate_image(path):
            os.remove(path)
            flash("File bukan gambar yang valid atau terlalu besar.", "danger")
            return redirect(request.url)
        
        # Process EXIF
        exif_text = run_exiftool_on_file(path)
        date_str, hour, minute = parse_exif_datetime(exif_text)
        lat, lon = parse_exif_gps(exif_text)
        
        status = "Pending"
        alasan = ""
        today_db = datetime.now().strftime("%Y:%m:%d")
        
        if not date_str:
            status = "Ditolak"
            alasan = "Foto tidak memiliki metadata waktu"
            flash("Foto tidak valid!", "danger")
        else:
            if date_str != today_db:
                status = "Ditolak"
                alasan = f"Tanggal EXIF ({date_str}) tidak sesuai hari ini ({today_db})"
                flash("Tanggal foto tidak sesuai!", "danger")
            else:
                if hour is not None and 6 <= hour <= 6:
                    status = "Disetujui"
                    alasan = f"Auto-approve: foto diambil jam {hour:02d}:{minute:02d} (06:00-06:59)"
                    flash(f"Absensi disetujui! Jam {hour:02d}:{minute:02d}", "success")
                else:
                    if lat is not None and lon is not None:
                        distance = haversine_meters(lat, lon, TARGET_LAT, TARGET_LON)
                        if distance <= RADIUS_METERS:
                            status = "Disetujui"
                            alasan = f"Auto-approve: lokasi {distance:.1f}m dari sekolah"
                            flash(f"Absensi disetujui! Lokasi: {distance:.1f}m", "success")
                        else:
                            status = "Ditolak"
                            alasan = f"Lokasi terlalu jauh ({distance:.1f}m dari sekolah)"
                            flash("Lokasi terlalu jauh!", "danger")
                    else:
                        status = "Ditolak"
                        if hour is not None:
                            alasan = f"Foto diambil jam {hour:02d}:{minute:02d} (bukan 06:00-06:59) dan tidak ada GPS"
                        else:
                            alasan = "Tidak ada data GPS dan waktu tidak valid"
                        flash("Foto harus diambil jam 06:00-06:59 atau di lokasi sekolah!", "danger")
        
        # Save to database
        conn = get_db_conn()
        c = conn.cursor()
        try:
            c.execute("""INSERT INTO absensi
                         (user_id, filename, tanggal, datetime_exif, latitude, longitude, status, alasan, exif_text)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (session['user_id'], filename, datetime.now().strftime("%Y-%m-%d"),
                       exif_text.splitlines()[0] if exif_text else None, lat, lon, status, alasan, exif_text))
            conn.commit()
        except Exception as e:
            conn.rollback()
            os.remove(path)  # Delete uploaded file if DB insert fails
            flash("Gagal menyimpan data absensi.", "danger")
        finally:
            conn.close()
        
        return redirect(url_for('upload'))
    
    # GET
    upload_count = count_today_uploads(session['user_id'])
    remaining = MAX_UPLOAD_PER_DAY - upload_count
    
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT filename,tanggal,status,alasan FROM absensi WHERE user_id=? ORDER BY id DESC LIMIT 50", 
              (session['user_id'],))
    rows = c.fetchall()
    conn.close()
    
    return render_template('index.html', username=session.get('nama'), uploads=rows, 
                         upload_count=upload_count, remaining=remaining, max_upload=MAX_UPLOAD_PER_DAY)

@app.route('/dashboard')
@admin_required
def dashboard():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("""SELECT a.id, u.nama, a.filename, a.tanggal, a.datetime_exif,
                        a.latitude, a.longitude, a.status, a.alasan, a.exif_text
                 FROM absensi a JOIN users u ON a.user_id=u.id
                 ORDER BY a.id DESC LIMIT 200""")
    rows = c.fetchall()
    conn.close()
    return render_template('admin.html', absensi=rows)

@app.route('/approve/<int:absen_id>')
@admin_required
def approve(absen_id):
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("UPDATE absensi SET status='Disetujui', alasan='Disetujui admin' WHERE id=?", (absen_id,))
    conn.commit()
    conn.close()
    flash("Absensi disetujui!", "success")
    return redirect(url_for('dashboard'))

@app.route('/reject/<int:absen_id>')
@admin_required
def reject(absen_id):
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("UPDATE absensi SET status='Ditolak', alasan='Ditolak admin' WHERE id=?", (absen_id,))
    conn.commit()
    conn.close()
    flash("Absensi ditolak!", "success")
    return redirect(url_for('dashboard'))

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    # Prevent directory traversal
    safe_filename = secure_filename(filename)
    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    
    # Check if file exists and is in upload folder
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        flash("File tidak ditemukan.", "danger")
        return redirect(url_for('upload'))
    
    return send_from_directory(UPLOAD_FOLDER, safe_filename)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logout berhasil!", "success")
    return redirect(url_for('login'))

@app.route('/favicon.ico')
def favicon():
    # Return empty response for favicon to avoid 404 errors
    return '', 204

@app.route('/admin/cleanup')
@admin_required
def manual_cleanup():
    """Manual cleanup trigger for admin"""
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        conn = get_db_conn()
        c = conn.cursor()
        
        c.execute("SELECT id, filename, tanggal FROM absensi WHERE tanggal < ?", (today,))
        old_records = c.fetchall()
        
        if not old_records:
            flash("Tidak ada data lama untuk dibersihkan.", "info")
            return redirect(url_for('dashboard'))
        
        success_count = 0
        fail_count = 0
        
        for record in old_records:
            file_path = os.path.join(UPLOAD_FOLDER, record['filename'])
            
            if os.path.exists(file_path):
                success, message = upload_to_backup_api(file_path, record['filename'])
                if success:
                    success_count += 1
                    try:
                        os.remove(file_path)
                    except:
                        pass
                else:
                    fail_count += 1
            
            c.execute("DELETE FROM absensi WHERE id=?", (record['id'],))
        
        conn.commit()
        conn.close()
        
        set_last_cleanup_date(today)
        
        flash(f"Cleanup selesai! {success_count} file diupload, {fail_count} gagal, {len(old_records)} record dihapus.", "success")
        
    except Exception as e:
        flash(f"Error saat cleanup: {str(e)[:100]}", "danger")
    
    return redirect(url_for('dashboard'))

# Error handlers
@app.errorhandler(413)
def too_large(e):
    flash("File terlalu besar! Maksimal 10MB.", "danger")
    return redirect(url_for('upload'))

@app.errorhandler(404)
def page_not_found(e):
    return '''
    <!doctype html>
    <html>
    <head><title>404 - Not Found</title></head>
    <body style="font-family: Arial; text-align: center; padding: 50px;">
        <h1>404 - Halaman Tidak Ditemukan</h1>
        <p>Halaman yang Anda cari tidak ada.</p>
        <a href="/" style="color: #3498db;">Kembali ke Home</a>
    </body>
    </html>
    ''', 404

@app.errorhandler(500)
def internal_error(e):
    return '''
    <!doctype html>
    <html>
    <head><title>500 - Server Error</title></head>
    <body style="font-family: Arial; text-align: center; padding: 50px;">
        <h1>500 - Server Error</h1>
        <p>Terjadi kesalahan pada server.</p>
        <a href="/" style="color: #3498db;">Kembali ke Home</a>
    </body>
    </html>
    ''', 500

# ===== run =====
if __name__ == '__main__':
    # PRODUCTION: Set debug=False and use proper WSGI server
    app.run(debug=True, host='0.0.0.0', port=8083)