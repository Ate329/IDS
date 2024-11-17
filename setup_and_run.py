import os
import subprocess
import sys
import time
import platform
import shutil
import logging

# Configure logging to output to both console and a file
LOG_FILE = 'setup.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),          # Console output
        logging.FileHandler(LOG_FILE, mode='w')     # File output
    ]
)

REPO_URL = "https://github.com/Ate329/IDS.git"
PROJECT_DIR = "IDS"
VENV_DIR = ".venv"
REQUIREMENTS_FILE = "requirements.txt"

def git_pull():
    """Clone the repository or pull the latest changes if it already exists."""
    if not os.path.exists(PROJECT_DIR):
        logging.info(f"Cloning repository from {REPO_URL}...")
        subprocess.run(["git", "clone", REPO_URL], check=True)
    else:
        logging.info("Pulling latest changes from the repository...")
        subprocess.run(["git", "-C", PROJECT_DIR, "pull"], check=True)

def virtualenv_exists(venv_path):
    """Check if the virtual environment already exists."""
    if platform.system() == "Windows":
        return os.path.exists(os.path.join(venv_path, "Scripts", "python.exe"))
    else:
        return os.path.exists(os.path.join(venv_path, "bin", "python"))

def get_virtualenv_paths(venv_path):
    """Get the paths to the Python and pip executables inside the virtual environment."""
    if platform.system() == "Windows":
        python_path = os.path.join(venv_path, "Scripts", "python.exe")
        pip_path = os.path.join(venv_path, "Scripts", "pip.exe")
    else:
        python_path = os.path.join(venv_path, "bin", "python")
        pip_path = os.path.join(venv_path, "bin", "pip")
    return python_path, pip_path

def setup_virtualenv():
    """Create and activate a virtual environment, and install dependencies."""
    venv_path = os.path.join(PROJECT_DIR, VENV_DIR)

    if virtualenv_exists(venv_path):
        logging.info("Virtual environment already exists. Skipping creation.")
        return

    # Find the Python interpreter
    python_executable = shutil.which("python") or shutil.which("python3")
    if not python_executable:
        logging.error("Python interpreter not found.")
        sys.exit(1)

    logging.info(f"Using Python interpreter at {python_executable}")
    logging.info("Creating virtual environment...")
    subprocess.run([python_executable, "-m", "venv", venv_path], check=True)

    # Get paths to pip and python inside the virtual environment
    python_path, pip_path = get_virtualenv_paths(venv_path)

    if not os.path.exists(pip_path):
        logging.error("pip not found in the virtual environment.")
        sys.exit(1)

    logging.info("Installing dependencies...")
    subprocess.run([pip_path, "install", "-r", os.path.join(PROJECT_DIR, REQUIREMENTS_FILE)], check=True)

def run_migrations():
    """Run makemigrations and migrate commands."""
    manage_py_dir = os.path.join(PROJECT_DIR, "ids_project")
    manage_py_path = os.path.join(manage_py_dir, "manage.py")
    venv_path = os.path.join(PROJECT_DIR, VENV_DIR)
    python_path, _ = get_virtualenv_paths(venv_path)

    if not os.path.exists(manage_py_path):
        logging.error(f"manage.py not found at {manage_py_path}")
        sys.exit(1)

    # Run makemigrations
    logging.info("Running makemigrations...")
    try:
        result = subprocess.run(
            [python_path, "manage.py", "makemigrations"],
            check=True,
            cwd=manage_py_dir,
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logging.info(f"Makemigrations completed successfully:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error during makemigrations: {e}")
        logging.error(f"Standard Output:\n{e.stdout}")
        logging.error(f"Error Output:\n{e.stderr}")
        sys.exit(1)

    # Run migrate
    logging.info("Applying database migrations...")
    try:
        result = subprocess.run(
            [python_path, "manage.py", "migrate"],
            check=True,
            cwd=manage_py_dir,
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logging.info(f"Migrations applied successfully:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error during migrate: {e}")
        logging.error(f"Standard Output:\n{e.stdout}")
        logging.error(f"Error Output:\n{e.stderr}")
        sys.exit(1)

def run_django():
    """Run the Django development server."""
    manage_py_dir = os.path.join(PROJECT_DIR, "ids_project")
    manage_py_path = os.path.join(manage_py_dir, "manage.py")
    venv_path = os.path.join(PROJECT_DIR, VENV_DIR)
    python_path, _ = get_virtualenv_paths(venv_path)

    if not os.path.exists(manage_py_path):
        logging.error(f"manage.py not found at {manage_py_path}")
        sys.exit(1)

    logging.info("Starting Django development server...")

    try:
        subprocess.run(
            [python_path, "manage.py", "runserver"],
            check=True,
            cwd=manage_py_dir,
            env=os.environ.copy()
        )
    except subprocess.CalledProcessError as e:
        logging.error(f"Subprocess error occurred: {e}")
        logging.error(f"Standard Output:\n{e.stdout}")
        logging.error(f"Error Output:\n{e.stderr}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        logging.info("Starting the setup process...")
        git_pull()
        setup_virtualenv()
        run_migrations()
        run_django()
    except subprocess.CalledProcessError as e:
        logging.error(f"Subprocess error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)
