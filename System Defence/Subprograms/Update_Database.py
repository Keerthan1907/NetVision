import os
import sqlite3
import requests
import time

script_dir = os.path.dirname(os.path.abspath(__file__))
log_path = os.path.join(script_dir, "update_log.txt")

def log_status(message):
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(message + "\n")

def fetch_and_save_file(url, directory, filename):
    if not os.path.exists(directory):
        os.makedirs(directory)

    filepath = os.path.join(directory, filename)
    
    if os.path.exists(filepath):
        log_status(f"ℹ️ Already exists: {filepath}")
        return filepath

    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open(filepath, 'w') as file:
                file.write(response.text)
            log_status(f"✅ Downloaded: {filename}")
            return filepath
        else:
            log_status(f"❌ Not found: {url}")
            return None
    except requests.RequestException as e:
        log_status(f"❌ Error downloading {url}: {e}")
        return None

def download_files(base_url, prefix):
    file_index = 1
    parent_dir = os.path.dirname(script_dir)
    directory = os.path.join(parent_dir, 'Malware Hash Database')
    files = []

    while True:
        url = f"{base_url}{file_index}.txt"
        filename = f"{prefix}_hashes_{file_index}.txt"
        filepath = fetch_and_save_file(url, directory, filename)
        if filepath:
            files.append(filepath)
        else:
            break
        file_index += 1

    return files

def create_database():
    parent_dir = os.path.dirname(script_dir)
    directory = os.path.join(parent_dir, 'Malware Hash Database')
    db_path = os.path.join(directory, "hashes.db")

    if os.path.exists(db_path):
        os.remove(db_path)
        log_status("♻️ Removed old antivirus signatures database.")
    else:
        log_status("📂 No existing database found, creating new...")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS md5 (hash TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS sha1 (hash TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS sha256 (hash TEXT)")
    conn.commit()
    return conn

def insert_hashes(conn, table, hashes):
    cursor = conn.cursor()
    cursor.executemany(f"INSERT INTO {table} (hash) VALUES (?)", [(h,) for h in hashes])
    conn.commit()
    log_status(f"✅ Inserted {len(hashes)} hashes into {table.upper()} table.")

def process_files(conn, prefix, files):
    all_hashes = []
    for file in files:
        with open(file, 'r') as f:
            hashes = f.read().splitlines()
            all_hashes.extend(hashes)
    insert_hashes(conn, prefix, all_hashes)

def update_antivirus_signatures():
    log_status("🚀 Starting antivirus signatures update...")

    base_urls = {
        "md5": "https://raw.githubusercontent.com/aaryanrlondhe/Malware-Hash-Database/main/MD5/md5_hashes_",
        "sha1": "https://raw.githubusercontent.com/aaryanrlondhe/Malware-Hash-Database/main/SHA1/sha1_hashes_",
        "sha256": "https://raw.githubusercontent.com/aaryanrlondhe/Malware-Hash-Database/main/SHA256/sha256_hashes_"
    }

    downloaded_files = {}
    for prefix, base_url in base_urls.items():
        log_status(f"⬇️ Downloading {prefix.upper()} files...")
        downloaded_files[prefix] = download_files(base_url, prefix)

    conn = create_database()
    for prefix, files in downloaded_files.items():
        process_files(conn, prefix, files)
    conn.close()

    log_status("✅ Antivirus Signatures updated successfully!")
    time.sleep(1)

if __name__ == "__main__":
    # Clear previous log
    with open(log_path, "w", encoding="utf-8") as log:
        log.write("🛡️ Update Log Initiated\n")
    update_antivirus_signatures()
