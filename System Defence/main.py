from flask import Flask, render_template, redirect, request, url_for, send_file
import os
import subprocess
import threading
import hashlib
import sqlite3
import shutil
from werkzeug.utils import secure_filename

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUBPROG_DIR = os.path.join(BASE_DIR, "Subprograms")
QUARANTINE_DIR = os.path.join(BASE_DIR, "Quarantine")
SCAN_LOG_FILE = os.path.join(SUBPROG_DIR, "scan_log.txt")
REALTIME_LOG_FILE = os.path.join(SUBPROG_DIR, "realtime_log.txt")
UPDATE_LOG_FILE = os.path.join(SUBPROG_DIR, "update_log.txt")
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'UploadedFiles')
DB_PATH = os.path.join(BASE_DIR, "Malware Hash Database", "hashes.db")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def run_full_scan_background():
    script_path = os.path.join(SUBPROG_DIR, "Full_Scan_Part_1.py")
    with open(SCAN_LOG_FILE, "w", encoding="utf-8") as f:
        f.write("🛠️ Full system scan started...\n")
        f.flush()
        process = subprocess.Popen(
            ['python', script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        for line in process.stdout:
            f.write(line)
            f.flush()
        process.stdout.close()
        process.wait()


def run_realtime_scan_background():
    script_path = os.path.join(SUBPROG_DIR, "Real_Time_Scan_Part_1.py")
    with open(REALTIME_LOG_FILE, "w", encoding="utf-8") as f:
        f.write("🛡️ Real-time scanning started...\n")
    subprocess.run(['python', script_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_update_signatures_background():
    script_path = os.path.join(SUBPROG_DIR, "update_database.py")
    with open(UPDATE_LOG_FILE, "w", encoding="utf-8") as f:
        f.write("🚀 Starting antivirus signature update...\n")
        f.flush()
        process = subprocess.Popen(
            ['python', script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        for line in process.stdout:
            f.write(line)
            f.flush()
        process.stdout.close()
        process.wait()

@app.route('/')
def index():
    message = request.args.get("msg")
    return render_template('index.html', message=message)

@app.route('/run_full_scan')
def run_full_scan():
    thread = threading.Thread(target=run_full_scan_background)
    thread.start()
    return redirect(url_for('scanning_page'))

@app.route('/scanning')
def scanning_page():
    return render_template('scanning.html')

@app.route('/get_scan_log')
def get_scan_log():
    try:
        if os.path.exists(SCAN_LOG_FILE):
            with open(SCAN_LOG_FILE, "r", encoding="utf-8") as f:
                return f.read(), 200, {'Content-Type': 'text/plain; charset=utf-8'}
        else:
            return "⏳ Waiting for scan to start...", 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        return f"⚠️ Error reading log: {e}", 500, {'Content-Type': 'text/plain; charset=utf-8'}



@app.route('/scan_file', methods=['GET', 'POST'])
def scan_file():
    result = None
    if request.method == 'POST':
        if 'file' not in request.files:
            result = "🚫 No file part"
        file = request.files['file']
        if file.filename == '':
            result = "🚫 No selected file"
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            hashes = get_file_hashes(file_path)
            if hashes:
                result = check_hashes_in_db(hashes, file_path)
            else:
                result = "❌ Failed to compute hashes."
    return render_template('scan_file.html', result=result)

@app.route('/start_real_time_scan')
def start_real_time_scan():
    thread = threading.Thread(target=run_realtime_scan_background)
    thread.start()
    return redirect(url_for('realtime_page'))

@app.route('/realtime')
def realtime_page():
    return render_template('realtime.html')

@app.route('/get_realtime_log')
def get_realtime_log():
    try:
        if os.path.exists(REALTIME_LOG_FILE):
            with open(REALTIME_LOG_FILE, "r", encoding="utf-8") as f:
                return f.read()
        else:
            return "⏳ Starting real-time scanner..."
    except Exception as e:
        return f"⚠️ Error reading real-time log: {e}"

@app.route('/open_quarantine')
def open_quarantine():
    try:
        files = os.listdir(QUARANTINE_DIR)
        files = [f for f in files if os.path.isfile(os.path.join(QUARANTINE_DIR, f))]
    except Exception as e:
        files = []
    return render_template('quarantine.html', files=files)

@app.route('/download_quarantine/<path:filename>')
def download_quarantine(filename):
    try:
        return send_file(os.path.join(QUARANTINE_DIR, filename), as_attachment=True)
    except Exception as e:
        return f"⚠️ Error downloading file: {e}", 404


@app.route('/run_update_signatures', methods=['POST'])
def run_update_signatures():
    thread = threading.Thread(target=run_update_signatures_background)
    thread.start()
    return "✅ Update process started."

@app.route('/get_update_log')
def get_update_log():
    try:
        if os.path.exists(UPDATE_LOG_FILE):
            with open(UPDATE_LOG_FILE, "r", encoding="utf-8") as f:
                return f.read()
        else:
            return "⏳ Waiting for update to begin..."
    except Exception as e:
        return f"⚠️ Error reading update log: {e}"

@app.route('/update_signatures')
def update_signatures():
    return redirect(url_for('update_page'))

@app.route('/update')
def update_page():
    return render_template('update.html')

@app.route('/close')
def close_app():
    return "<h2>🔒 Antivirus Closed. See you again soon!</h2>"

def run_script(script_name):
    try:
        script_path = os.path.join(SUBPROG_DIR, script_name)
        subprocess.run(['python', script_path], check=True)
    except subprocess.CalledProcessError as e:
        return f"🚫 Error: {e}"
    except FileNotFoundError:
        return "🚫 Script not found!"
    return "✅ Task completed!"

def get_file_hashes(file_path):
    hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)
        return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
    except Exception:
        return None

def check_hashes_in_db(hashes, file_path):
    if not os.path.exists(DB_PATH):
        return "🚫 Database not found."

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for hash_type, hash_value in hashes.items():
        cursor.execute(f"SELECT * FROM {hash_type} WHERE hash = ?", (hash_value,))
        result = cursor.fetchone()
        if result:
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(QUARANTINE_DIR, file_name)
            shutil.move(file_path, quarantine_path)
            conn.close()
            return "🚨 Virus detected! File moved to quarantine."

    conn.close()
    return "✅ File is clean!"

if __name__ == '__main__':
    app.run(debug=True)
