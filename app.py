from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
import os
import sqlite3
import subprocess
from datetime import datetime
from math import radians, sin, cos, sqrt, atan2
import re
import pathlib

app = Flask(__name__)
app.secret_key = "supersecret_change_this"
BASE_DIR = pathlib.Path(__file__).parent
UPLOAD_FOLDER = str(BASE_DIR / "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DATABASE = str(BASE_DIR / "database.db")

# ====== Config ======
# Target koordinat (lokasi sekolah / plus code 73Q4+6M4)
TARGET_LAT = -6.741702
TARGET_LON = 111.036899
RADIUS_METERS = 50  # 50 meter

# Jadwal piket (bisa diubah sesuai kebutuhan)
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

# ====== Helpers ======
def get_db_conn():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def haversine_meters(lat1, lon1, lat2, lon2):
    # return distance in meters
    R = 6371000.0
    phi1 = radians(lat1)
    phi2 = radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)
    a = sin(dphi/2)**2 + cos(phi1)*cos(phi2)*sin(dlambda/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

def make_username(name):
    # username = nama depan, lowercase, alphanumeric
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
                    nama TEXT,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT DEFAULT 'petugas'
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS absensi (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    filename TEXT,
                    tanggal TEXT,
                    datetime_exif TEXT,
                    latitude REAL,
                    longitude REAL,
                    status TEXT,
                    alasan TEXT,
                    exif_text TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                 )''')
    conn.commit()
    conn.close()

def seed_users_from_jadwal():
    # buat user dari jadwal, password = username
    conn = get_db_conn()
    c = conn.cursor()
    for day, names in JADWAL.items():
        for full in names:
            username = make_username(full)
            password = username
            c.execute("SELECT id FROM users WHERE username=?", (username,))
            if c.fetchone():
                # update nama & password agar sesuai kebijakan terbaru
                c.execute("UPDATE users SET nama=?, password=?, role='petugas' WHERE username=?", (full, password, username))
            else:
                c.execute("INSERT INTO users (nama, username, password, role) VALUES (?,?,?,?)", (full, username, password, 'petugas'))
    # ensure admin
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (nama, username, password, role) VALUES (?,?,?,?)", ('Admin','admin','admin','admin'))
    conn.commit()
    conn.close()

def run_exiftool_on_file(path):
    # return exif_text (string)
    try:
        p = subprocess.run(['exiftool', path], capture_output=True, text=True, timeout=6)
        return p.stdout or ""
    except Exception as e:
        return f"ExifTool error: {e}"

def parse_exif_datetime(exif_text):
    # try find date/time with flexible regex, return (date_str, hour, minute)
    # date_str format used in DB will be YYYY:MM:DD (consistent)
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
            continue  # skip baris kosong / aneh

        key, val = line.split(":", 1)
        val = val.strip()

        if "GPS Latitude" in key:
            try:
                lat = float(val.split()[0])
            except:
                # kalau bukan decimal, coba deteksi dari format derajat
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

# ====== Routes ======
@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or "").strip().lower()
        password = (request.form.get('password') or "").strip()
        conn = get_db_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nama'] = user['nama']
            session['role'] = user['role']
            return redirect(url_for('dashboard' if user['role']=='admin' else 'upload'))
        else:
            flash("Login gagal: username/password salah", "danger")
            # fallthrough: re-render login with jadwal
    return render_template('login.html', jadwal=JADWAL)

@app.route('/upload', methods=['GET','POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or f.filename == '':
            flash("Pilih file dulu.", "warning")
            return redirect(request.url)

        # safe filename with timestamp
        safe = re.sub(r'[^a-zA-Z0-9._-]', '_', f.filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{timestamp}_{safe}"
        path = os.path.join(UPLOAD_FOLDER, filename)
        f.save(path)

        # run exiftool
        exif_text = run_exiftool_on_file(path)

        # parse exif time and gps
        date_str, hour, minute = parse_exif_datetime(exif_text)
        lat, lon = parse_exif_gps(exif_text)

        status = "Pending"
        alasan = ""

        today_db = datetime.now().strftime("%Y:%m:%d")

        # if no datetime EXIF -> reject
        if not date_str:
            status = "Ditolak"
            alasan = "Foto tidak memiliki metadata waktu"
            flash("Jangan coba bohong!", "danger")
        else:
            # date must match today
            if date_str != today_db:
                status = "Ditolak"
                alasan = f"Tanggal EXIF ({date_str}) tidak sesuai hari ini ({today_db})"
                flash("Jangan coba bohong!", "danger")
            else:
                # PERBAIKAN: Cek waktu foto diambil (dari EXIF), bukan waktu upload
                # Auto approve jika foto diambil antara jam 06:00-06:59
                if hour is not None and 6 <= hour <= 6:
                    status = "Disetujui"
                    alasan = f"Auto-approve: foto diambil jam {hour:02d}:{minute:02d} (06:00-06:59)"
                    flash(f"Absensi disetujui! Foto diambil jam {hour:02d}:{minute:02d}", "success")
                else:
                    # Jika tidak dalam rentang waktu 06:00-06:59, cek GPS
                    if lat is not None and lon is not None:
                        distance = haversine_meters(lat, lon, TARGET_LAT, TARGET_LON)
                        if distance <= RADIUS_METERS:
                            status = "Disetujui"
                            alasan = f"Auto-approve: lokasi {distance:.1f}m dari sekolah"
                            flash(f"Absensi disetujui! Lokasi {distance:.1f}m dari sekolah", "success")
                        else:
                            status = "Ditolak"
                            alasan = f"Lokasi terlalu jauh ({distance:.1f}m dari sekolah)"
                            flash("Jangan coba bohong! Lokasi terlalu jauh dari sekolah.", "danger")
                    else:
                        # Tidak ada GPS dan waktu tidak memenuhi syarat
                        status = "Ditolak"
                        if hour is not None:
                            alasan = f"Foto diambil jam {hour:02d}:{minute:02d} (bukan jam 06:00-06:59) dan tidak ada data GPS"
                        else:
                            alasan = "Tidak ada data GPS dan waktu tidak valid"
                        flash("Jangan coba bohong! Foto harus diambil jam 06:00-06:59 atau di lokasi sekolah.", "danger")

        # save row
        conn = get_db_conn()
        c = conn.cursor()
        c.execute("""INSERT INTO absensi
                     (user_id, filename, tanggal, datetime_exif, latitude, longitude, status, alasan, exif_text)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (session['user_id'], filename, datetime.now().strftime("%Y-%m-%d"),
                   exif_text.splitlines()[0] if exif_text else None, lat, lon, status, alasan, exif_text))
        conn.commit()
        conn.close()

        return redirect(url_for('upload'))

    # GET
    # show user uploads (filename,tanggal,status,alasan)
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT filename,tanggal,status,alasan FROM absensi WHERE user_id=? ORDER BY id DESC", (session['user_id'],))
    rows = c.fetchall()
    conn.close()
    return render_template('index.html', username=session.get('nama'), uploads=rows)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # only admin should view all; but allow admin only
    if session.get('role') != 'admin':
        flash("Akses ditolak: admin only", "danger")
        return redirect(url_for('upload'))

    conn = get_db_conn()
    c = conn.cursor()
    c.execute("""SELECT a.id, u.nama, a.filename, a.tanggal, a.datetime_exif,
                        a.latitude, a.longitude, a.status, a.alasan, a.exif_text
                 FROM absensi a JOIN users u ON a.user_id=u.id
                 ORDER BY a.id DESC""")
    rows = c.fetchall()
    conn.close()
    return render_template('admin.html', absensi=rows)

@app.route('/approve/<int:absen_id>')
def approve(absen_id):
    if session.get('role') != 'admin':
        flash("Akses ditolak", "danger")
        return redirect(url_for('login'))
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("UPDATE absensi SET status='Disetujui', alasan='Disetujui admin' WHERE id=?", (absen_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/reject/<int:absen_id>')
def reject(absen_id):
    if session.get('role') != 'admin':
        flash("Akses ditolak", "danger")
        return redirect(url_for('login'))
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("UPDATE absensi SET status='Ditolak', alasan='Ditolak admin' WHERE id=?", (absen_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ===== run =====
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8083)