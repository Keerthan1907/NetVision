import os
import hashlib
import sqlite3
import shutil
import getpass
import psutil
from plyer import notification
from winotify import Notification, audio  # Windows toast
import concurrent.futures

# Paths
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
db_path = os.path.join(parent_dir, 'Malware Hash Database', 'hashes.db')
quarantine_path = os.path.join(parent_dir, 'Quarantine')
log_file_path = os.path.join(script_dir, 'scan_log.txt')
logo_path = os.path.join(parent_dir, 'Logo', 'Logo.ico')

os.makedirs(quarantine_path, exist_ok=True)

def write_log(msg):
    with open(log_file_path, 'a', encoding='utf-8') as f:
        f.write(msg + '\n')
    print(msg)

def get_file_hashes(file_path):
    hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)
        return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
    except Exception as e:
        write_log(f"⚠️ Error hashing {file_path}: {e}")
        return None

def check_hashes_in_db(hashes, file_path):
    if not os.path.exists(db_path):
        write_log("🚫 Malware hash database not found!")
        return
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        for hash_type, hash_value in hashes.items():
            cursor.execute(f"SELECT * FROM {hash_type} WHERE hash = ?", (hash_value,))
            result = cursor.fetchone()
            if result:
                write_log(f"🚨 Virus detected in {file_path} [matched {hash_type.upper()}]")
                notify_virus_detected(file_path)
                move_to_quarantine(file_path)
                break
    except Exception as e:
        write_log(f"⚠️ DB check error for {file_path}: {e}")
    finally:
        conn.close()

def notify_virus_detected(file_path):
    toast = Notification(app_id="Secure Drive",
                         title="🚨 Virus Detected!",
                         msg=f"The file '{os.path.basename(file_path)}' is malicious and has been quarantined.",
                         icon=logo_path)
    toast.set_audio(audio.Default, loop=False)
    toast.show()

def move_to_quarantine(file_path):
    try:
        shutil.move(file_path, os.path.join(quarantine_path, os.path.basename(file_path)))
        write_log(f"🔒 File moved to quarantine: {file_path}")
    except Exception as e:
        write_log(f"⚠️ Error moving file to quarantine: {e}")

def scan_file(file_path):
    write_log(f"🔍 Scanning file: {file_path}")
    hashes = get_file_hashes(file_path)
    if hashes:
        check_hashes_in_db(hashes, file_path)

def list_all_files():
    for partition in psutil.disk_partitions():
        if 'cdrom' in partition.opts or partition.fstype == '':
            continue
        root = partition.mountpoint
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                yield file_path

def main():
    write_log("\n🛡️ Full system scan started...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for file_path in list_all_files():
            executor.submit(scan_file, file_path)
    write_log("✅ Full system scan completed.")

if __name__ == '__main__':
    main()
