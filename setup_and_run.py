import os
import subprocess
import sys
import time
import webbrowser
import threading

REPO_URL = "https://github.com/Ate329/IDS.git"
PROJECT_DIR = "IDS"
VENV_DIR = ".venv"
REQUIREMENTS_FILE = "requirements.txt"


def git_pull():
    """Pull the latest changes from the repository."""
    if not os.path.exists(PROJECT_DIR):
        print(f"Cloning repository from {REPO_URL}...")
        subprocess.run(["git", "clone", REPO_URL], check=True)
    else:
        print("Pulling latest changes...")
        subprocess.run(["git", "-C", PROJECT_DIR, "pull"], check=True)


def setup_virtualenv():
    """Create and activate a virtual environment, and install dependencies."""
    venv_path = os.path.join(PROJECT_DIR, VENV_DIR)
    if not os.path.exists(venv_path):
        print("Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", venv_path], check=True)

    pip_path = os.path.join(venv_path, "bin", "pip")
    if not os.path.exists(pip_path):
        pip_path = os.path.join(venv_path, "Scripts", "pip.exe")  # For Windows

    print("Installing dependencies...")
    subprocess.run([pip_path, "install", "-r", os.path.join(PROJECT_DIR, REQUIREMENTS_FILE)], check=True)


def run_migrations():
    """Run database migrations."""
    manage_py_path = os.path.join(PROJECT_DIR, "ids_project", "manage.py")
    python_path = os.path.join(PROJECT_DIR, VENV_DIR, "bin", "python")
    if not os.path.exists(python_path):
        python_path = os.path.join(PROJECT_DIR, VENV_DIR, "Scripts", "python.exe")  # For Windows

    print("Applying database migrations...")
    subprocess.run([python_path, manage_py_path, "migrate"], check=True)


def open_browser():
    """Open the default web browser after a delay."""
    time.sleep(3)  # Wait for the server to start
    webbrowser.open("http://127.0.0.1:8000")


def run_django():
    """Run the Django development server and open the browser."""
    manage_py_path = os.path.join(PROJECT_DIR, "ids_project", "manage.py")
    python_path = os.path.join(PROJECT_DIR, VENV_DIR, "bin", "python")
    if not os.path.exists(python_path):
        python_path = os.path.join(PROJECT_DIR, VENV_DIR, "Scripts", "python.exe")  # For Windows

    print("Starting Django development server...")
    threading.Thread(target=open_browser, daemon=True).start()  # Start browser in a separate thread
    subprocess.run([python_path, manage_py_path, "runserver"], check=True)


if __name__ == "__main__":
    try:
        git_pull()
        setup_virtualenv()
        run_migrations()
        run_django()
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")
        sys.exit(1)
