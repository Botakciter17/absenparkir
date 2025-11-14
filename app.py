from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
import os
import sqlite3
import subprocess
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2
import re
import pathlib
import secrets
from functools import wraps
from werkzeug.utils import secure_filename
import bleach
from PIL import Image
from collections import deque

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB

BASE_DIR = pathlib.Path(__file__).parent
UPLOAD_FOLDER = str(BASE_DIR / "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DATABASE = str(BASE_DIR / "database.db")

# ====== Config ======
TARGET_LAT = -6.741702
TARGET_LON = 111.036899
RADIUS_METERS = 50
MAX_UPLOAD_PER_DAY = 3

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

# ====== Rate limit (per nama) ======
MAX_ATTEMPTS_PER_NAME = 5
NAME_WINDOW_SECONDS = 300
name_attempts = {}  # nama_lower -> deque[timestamps]

def _prune(deq: deque, window_seconds: int, now: datetime):
    cutoff = now.timestamp() - window_seconds
    while deq and deq[0] < cutoff:
        deq.popleft()

def is_blocked(nama_lower: str):
    """Kembalikan (blocked, retry_after, remaining)"""
    now = datetime.now()
    deq = name_attempts.setdefault(nama_lower or "-", deque())
    _prune(deq, NAME_WINDOW_SECONDS, now)

    if len(deq) >= MAX_ATTEMPTS_PER_NAME:
        retry_after = int(NAME_WINDOW_SECONDS - (now.timestamp() - deq[0]))
        return True, retry_after, 0

    remaining = MAX_ATTEMPTS_PER_NAME - len(deq)
    return False, None, remaining

def note_failed(nama_lower: str):
    ts = datetime.now().timestamp()
    name_attempts.setdefault(nama_lower or "-", deque()).append(ts)

def reset_name(nama_lower: str):
    name_attempts.pop(nama_lower or "-", None)

# ====== Security Helpers ======
def sanitize_input(text):
    if not text:
        return ""
    return bleach.clean(str(text).strip())

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Silakan login terlebih dahulu", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
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
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(file_path):
    try:
        with Image.open(file_path) as img:
            img.verify()
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            return False
        with Image.open(file_path) as img:
            if img.format.lower() not in ['jpeg', 'png', 'gif', 'bmp', 'webp']:
                return False
        return True
    except Exception:
        return False

def count_today_uploads(user_id):
    conn = get_db_conn()
    c = conn.cursor()
    today = datetime.now().strftime("%Y-%m-%d")
    c.execute("SELECT COUNT(*) as count FROM absensi WHERE user_id=? AND tanggal=?", (user_id, today))
    result = c.fetchone()
    conn.close()
    return result['count'] if result else 0

def haversine_meters(lat1, lon1, lat2, lon2):
    R = 6371000.0
    phi1 = radians(lat1); phi2 = radians(lat2)
    dphi = radians(lat2 - lat1); dlambda = radians(lon2 - lon1)
    a = sin(dphi/2)**2 + cos(phi1)*cos(phi2)*sin(dlambda/2)**2
    return 2*R*atan2(sqrt(a), sqrt(1-a))

def make_username(name):
    first = name.strip().split()[0]
    uname = re.sub(r'[^a-zA-Z0-9]', '', first).lower()
    if not uname:
        uname = re.sub(r'[^a-zA-Z0-9]', '', name).lower()[:8]
    return uname

def ensure_db():
    conn = get_db_conn()
    c = conn.cursor()
    
    # Cek apakah tabel users sudah ada
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    table_exists = c.fetchone()
    
    if table_exists:
        # Jika tabel lama ada dengan kolom username, drop dan buat ulang
        c.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in c.fetchall()]
        if 'username' in columns:
            print("Migrating database: dropping old users table...")
            c.execute("DROP TABLE IF EXISTS users")
            c.execute("DROP TABLE IF EXISTS absensi")
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nama TEXT NOT NULL UNIQUE,
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
                    jam_datang TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                 )''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_absensi_user_tanggal ON absensi(user_id, tanggal)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_absensi_status ON absensi(status)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_absensi_jenis ON absensi(jenis)''')
    conn.commit()
    conn.close()

def seed_users_from_jadwal():
    conn = get_db_conn()
    c = conn.cursor()
    for _, names in JADWAL.items():
        for full in names:
            full_upper = full.upper()
            c.execute("SELECT id FROM users WHERE nama=?", (full_upper,))
            if not c.fetchone():
                c.execute("INSERT INTO users (nama, role) VALUES (?,?)", (full_upper, 'petugas'))
    # admin
    c.execute("SELECT id FROM users WHERE nama='ADMIN'")
    if not c.fetchone():
        c.execute("INSERT INTO users (nama, role) VALUES (?,?)", ('ADMIN', 'admin'))
    conn.commit()
    conn.close()

def run_exiftool_on_file(path):
    try:
        if not os.path.exists(path):
            return "File not found"
        p = subprocess.run(['exiftool', path], capture_output=True, text=True, timeout=6)
        return p.stdout or ""
    except subprocess.TimeoutExpired:
        return "ExifTool timeout"
    except Exception as e:
        return f"ExifTool error: {str(e)[:100]}"

def parse_exif_datetime(exif_text):
    m = re.search(r'(\d{4}[:\-]\d{2}[:\-]\d{2})[ T](\d{2}):(\d{2})', exif_text)
    if m:
        date_part = m.group(1).replace('-', ':')
        hour = int(m.group(2)); minute = int(m.group(3))
        return date_part, hour, minute
    return None, None, None

def parse_exif_gps(exif_text):
    lat = None; lon = None
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
                    if ref.upper() == 'S': lat = -lat
        if "GPS Longitude" in key:
            try:
                lon = float(val.split()[0])
            except:
                m = re.search(r'(\d+)\s*deg\s*(\d+)\'\s*([\d.]+)"\s*([EW])', val)
                if m:
                    d, m_, s, ref = m.groups()
                    lon = int(d) + int(m_) / 60 + float(s) / 3600
                    if ref.upper() == 'W': lon = -lon
    return lat, lon

# ====== Init DB & seed ======
ensure_db()
seed_users_from_jadwal()

# ====== Security Headers Middleware ======
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ====== Routes ======
@app.route('/', methods=['GET','POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard' if session.get('role')=='admin' else 'upload'))

    if request.method == 'POST':
        nama = sanitize_input(request.form.get('nama', '')).upper()
        password = sanitize_input(request.form.get('password', ''))

        if not nama:
            flash("Nama harus diisi", "warning")
            return render_template('login.html', jadwal=JADWAL)

        # Khusus admin perlu password
        if nama == 'ADMIN':
            if not password:
                flash("Admin harus memasukkan password!", "warning")
                return render_template('login.html', jadwal=JADWAL, show_password=True)
            if password != 'pwosis7':
                flash("Password admin salah!", "danger")
                return render_template('login.html', jadwal=JADWAL, show_password=True)

        # cek rate limit
        nama_lower = nama.lower()
        blocked, retry_after, remaining = is_blocked(nama_lower)
        if blocked:
            minutes = max(1, (retry_after or 60) // 60)
            flash(f"Terlalu banyak percobaan. Coba lagi sekitar {minutes} menit.", "danger")
            return render_template('login.html', jadwal=JADWAL)

        conn = get_db_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE nama=?", (nama,))
        user = c.fetchone()
        conn.close()

        if user:
            reset_name(nama_lower)
            session.permanent = True
            session['user_id'] = user['id']
            session['nama'] = user['nama']
            session['role'] = user['role']
            session['csrf_token'] = secrets.token_hex(16)
            flash(f"Selamat datang, {user['nama']}!", "success")
            return redirect(url_for('dashboard' if user['role']=='admin' else 'upload'))
        else:
            note_failed(nama_lower)
            _, _, remain = is_blocked(nama_lower)
            flash(f"Nama tidak ditemukan! Sisa percobaan: {remain}", "danger")
            return render_template('login.html', jadwal=JADWAL)

    return render_template('login.html', jadwal=JADWAL)

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    if request.method == 'POST':
        if not session.get('csrf_token'):
            flash("Session expired. Please login again.", "danger")
            return redirect(url_for('login'))

        jam_datang_raw = sanitize_input(request.form.get('jam_datang', ''))
        if not jam_datang_raw or not re.match(r'^\d{2}:\d{2}$', jam_datang_raw):
            flash("Jam datang wajib diisi (format HH:MM).", "danger")
            return redirect(request.url)
        try:
            jam_datang = datetime.strptime(jam_datang_raw, "%H:%M").strftime("%H:%M")
        except ValueError:
            flash("Format jam datang tidak valid.", "danger")
            return redirect(request.url)

        upload_count = count_today_uploads(session['user_id'])
        if upload_count >= MAX_UPLOAD_PER_DAY:
            flash(f"Maksimal {MAX_UPLOAD_PER_DAY} kali upload per hari.", "danger")
            return redirect(request.url)

        f = request.files.get('file')
        if not f or f.filename == '':
            flash("Pilih file dulu.", "warning")
            return redirect(request.url)
        if not allowed_file(f.filename):
            flash("File harus berupa gambar (jpg, jpeg, png, gif, bmp, webp).", "danger")
            return redirect(request.url)

        original_filename = secure_filename(f.filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_string = secrets.token_hex(4)
        filename = f"{timestamp}_{random_string}_{original_filename}"
        path = os.path.join(UPLOAD_FOLDER, filename)
        try:
            f.save(path)
        except Exception:
            flash("Gagal menyimpan file.", "danger")
            return redirect(request.url)

        if not validate_image(path):
            os.remove(path)
            flash("File bukan gambar yang valid atau terlalu besar.", "danger")
            return redirect(request.url)

        exif_text = run_exiftool_on_file(path)
        date_str, hour, minute = parse_exif_datetime(exif_text)
        lat, lon = parse_exif_gps(exif_text)

        status = "Pending"
        alasan = ""
        jenis = "hadir"
        keterangan_izin = None

        today_db = datetime.now().strftime("%Y:%m:%d")
        if not date_str:
            status = "Ditolak"; alasan = "Foto tidak memiliki metadata waktu"
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

        conn = get_db_conn()
        c = conn.cursor()
        try:
            c.execute("""INSERT INTO absensi
                         (user_id, filename, tanggal, datetime_exif, latitude, longitude, status, alasan, exif_text, jenis, keterangan_izin, jam_datang)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (session['user_id'], filename, datetime.now().strftime("%Y-%m-%d"),
                       exif_text.splitlines()[0] if exif_text else None, lat, lon, status, alasan, exif_text,
                       jenis, keterangan_izin, jam_datang))
            conn.commit()
        except Exception:
            conn.rollback()
            os.remove(path)
            flash("Gagal menyimpan data absensi.", "danger")
        finally:
            conn.close()
        return redirect(url_for('upload'))

    upload_count = count_today_uploads(session['user_id'])
    remaining = MAX_UPLOAD_PER_DAY - upload_count
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("""SELECT filename,tanggal,jenis,status,alasan,keterangan_izin,jam_datang 
                 FROM absensi WHERE user_id=? ORDER BY id DESC LIMIT 50""", 
              (session['user_id'],))
    rows = c.fetchall()
    conn.close()
    return render_template('index.html', username=session.get('nama'), uploads=rows, 
                         upload_count=upload_count, remaining=remaining, max_upload=MAX_UPLOAD_PER_DAY)

@app.route('/izin', methods=['GET','POST'])
@login_required
def izin():
    if request.method == 'POST':
        if not session.get('csrf_token'):
            flash("Session expired. Please login again.", "danger")
            return redirect(url_for('login'))

        upload_count = count_today_uploads(session['user_id'])
        if upload_count >= MAX_UPLOAD_PER_DAY:
            flash(f"Maksimal {MAX_UPLOAD_PER_DAY} kali upload per hari.", "danger")
            return redirect(request.url)

        f = request.files.get('file')
        ket = sanitize_input(request.form.get('keterangan_izin', ''))

        if not f or f.filename == '':
            flash("Pilih file dulu.", "warning")
            return redirect(request.url)
        if len(ket) < 10:
            flash("Keterangan izin minimal 10 karakter.", "danger")
            return redirect(request.url)
        if not allowed_file(f.filename):
            flash("File harus berupa gambar (jpg, jpeg, png, gif, bmp, webp).", "danger")
            return redirect(request.url)

        original_filename = secure_filename(f.filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_string = secrets.token_hex(4)
        filename = f"{timestamp}_{random_string}_{original_filename}"
        path = os.path.join(UPLOAD_FOLDER, filename)
        try:
            f.save(path)
        except Exception:
            flash("Gagal menyimpan file.", "danger")
            return redirect(request.url)

        if not validate_image(path):
            os.remove(path)
            flash("File bukan gambar yang valid atau terlalu besar.", "danger")
            return redirect(request.url)

        exif_text = run_exiftool_on_file(path)
        lat, lon = parse_exif_gps(exif_text)
        date_str, hour, minute = parse_exif_datetime(exif_text)

        jenis = "izin"
        status = "Pending"
        alasan = "Menunggu verifikasi admin"

        conn = get_db_conn()
        c = conn.cursor()
        try:
            c.execute("""INSERT INTO absensi
                         (user_id, filename, tanggal, datetime_exif, latitude, longitude, status, alasan, exif_text, jenis, keterangan_izin, jam_datang)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (session['user_id'], filename, datetime.now().strftime("%Y-%m-%d"),
                       exif_text.splitlines()[0] if exif_text else None, lat, lon, status, alasan, exif_text, jenis, ket, None))
            conn.commit()
            flash("Pengajuan izin terkirim. Menunggu verifikasi admin.", "success")
        except Exception:
            conn.rollback()
            os.remove(path)
            flash("Gagal menyimpan pengajuan izin.", "danger")
        finally:
            conn.close()
        return redirect(url_for('izin'))

    conn = get_db_conn()
    c = conn.cursor()
    c.execute("""SELECT filename,tanggal,jenis,status,alasan,keterangan_izin,jam_datang 
                 FROM absensi WHERE user_id=? AND jenis='izin'
                 ORDER BY id DESC LIMIT 50""", (session['user_id'],))
    rows = c.fetchall()
    conn.close()
    return render_template('izin.html', username=session.get('nama'), uploads=rows)

@app.route('/dashboard')
@admin_required
def dashboard():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("""SELECT a.id, u.nama, a.filename, a.tanggal, a.datetime_exif,
                        a.latitude, a.longitude, a.status, a.alasan, a.exif_text,
                        a.jenis, a.keterangan_izin, a.jam_datang
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
    safe_filename = secure_filename(filename)
    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
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
    return '', 204

# Error handlers
@app.errorhandler(413)
def too_large(e):
    flash("File terlalu besar! Maksimal 10MB.", "danger")
    return redirect(url_for('upload'))

@app.errorhandler(404)
def page_not_found(e):
    return '<h1>404 - Halaman Tidak Ditemukan</h1><a href="/">Kembali</a>', 404

@app.errorhandler(500)
def internal_error(e):
    return '<h1>500 - Server Error</h1><a href="/">Kembali</a>', 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8083)