import os
import subprocess
import psutil

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_log.txt")

def write_log(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def run_full_system_scan():
    write_log("🛠️  Initializing full system scan script...")
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(script_dir)
        sub_dir2 = "Subprograms"
        file_name = "Full_Scan_Part_2.py"
        file_path = os.path.join(parent_dir, sub_dir2, file_name)

        subprocess.run(['python', file_path], check=True)

        write_log("✅ Full system scan completed.")
        return "✅ Scan completed successfully."

    except FileNotFoundError:
        write_log("🚫 Error: Full_Scan_Part_2.py file not found.")
        return "🚫 Full_Scan_Part_2.py not found."
    except Exception as e:
        write_log(f"⚠️ Error: {e}")
        return f"⚠️ Error: {e}"

if __name__ == "__main__":
    run_full_system_scan()
