import subprocess
import sys

def build():
    print("Building Firewall Rule Review standalone application...")
    
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--add-data", "templates;templates",
        "--add-data", "static;static",
        "--name", "FirewallRuleReview",
        "start.py"
    ]
    
    subprocess.run(cmd, check=True)
    print("Build complete! The executable is located in the 'dist' folder.")

if __name__ == "__main__":
    build()
