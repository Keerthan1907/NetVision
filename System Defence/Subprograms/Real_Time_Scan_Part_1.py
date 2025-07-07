import os
import subprocess
import psutil

def real_time_scan():
    print("🛠️ Initializing real-time scan script...")
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "realtime_log.txt")
    try:
        with open(log_path, "w", encoding="utf-8") as log:
            log.write("🛡️ Real-time scan initialized...\n")

        script_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(script_dir)
        sub_dir2 = "Subprograms"
        file_name = "Real_Time_Scan_Part_2.py"
        file_path = os.path.join(parent_dir, sub_dir2, file_name)
        
        subprocess.Popen(['python', file_path], creationflags=subprocess.CREATE_NEW_CONSOLE)

        with open(log_path, "a", encoding="utf-8") as log:
            log.write("🚀 Real-time scan started.\n")

    except FileNotFoundError:
        with open(log_path, "a", encoding="utf-8") as log:
            log.write("🚫 File not found!\n")
    except Exception as e:
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(f"⚠️ Error: {e}\n")

if __name__ == "__main__":
    real_time_scan()
