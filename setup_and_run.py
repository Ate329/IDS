import os
import subprocess
import sys
import platform
import shutil
import logging
import traceback

# -----------------------------
# Configuration Variables
# -----------------------------
REPO_URL = "https://github.com/Ate329/IDS.git"
PROJECT_DIR = os.getcwd()  # Use current directory
VENV_DIR = ".venv"
REQUIREMENTS_FILE = "requirements.txt"
CSV_FILE_NAME = "traffic_data.csv"
LOG_FILE = 'setup.log'

# -----------------------------
# Logging Configuration
# -----------------------------
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),          # Console output
        logging.FileHandler(LOG_FILE, mode='w')     # File output
    ]
)

# -----------------------------
# Helper Functions
# -----------------------------

def git_pull():
    """Clone the repository or pull the latest changes if it already exists."""
    if not os.path.exists(os.path.join(PROJECT_DIR, '.git')):
        logging.info(f"Cloning repository from {REPO_URL} into current directory...")
        try:
            subprocess.run(["git", "clone", REPO_URL, "."], check=True)
            logging.info("Repository cloned successfully.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to clone repository: {e}")
            sys.exit(1)
    else:
        logging.info("Repository already exists. Pulling latest changes...")
        try:
            subprocess.run(["git", "pull"], check=True, cwd=PROJECT_DIR)
            logging.info("Repository updated successfully.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to pull latest changes: {e}")
            sys.exit(1)

def virtualenv_exists(venv_path):
    """Check if the virtual environment already exists."""
    python_executable = os.path.join(venv_path, "Scripts", "python.exe") if platform.system() == "Windows" else os.path.join(venv_path, "bin", "python")
    return os.path.exists(python_executable)

def get_virtualenv_paths(venv_path):
    """Get the paths to the Python and pip executables inside the virtual environment."""
    if platform.system() == "Windows":
        python_path = os.path.abspath(os.path.join(venv_path, "Scripts", "python.exe"))
        pip_path = os.path.abspath(os.path.join(venv_path, "Scripts", "pip.exe"))
    else:
        python_path = os.path.abspath(os.path.join(venv_path, "bin", "python"))
        pip_path = os.path.abspath(os.path.join(venv_path, "bin", "pip"))
    return python_path, pip_path

def setup_virtualenv():
    """Create and activate a virtual environment, and install dependencies."""
    venv_path = os.path.join(PROJECT_DIR, VENV_DIR)

    if virtualenv_exists(venv_path):
        logging.info("Virtual environment already exists. Skipping creation.")
    else:
        # Find the Python interpreter
        python_executable = shutil.which("python") or shutil.which("python3")
        if not python_executable:
            logging.error("Python interpreter not found in PATH.")
            sys.exit(1)

        logging.info(f"Using Python interpreter at {python_executable}")
        logging.info("Creating virtual environment...")
        try:
            subprocess.run([python_executable, "-m", "venv", venv_path], check=True)
            logging.info("Virtual environment created successfully.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to create virtual environment: {e}")
            sys.exit(1)

    # Get paths to pip and python inside the virtual environment
    python_path, pip_path = get_virtualenv_paths(venv_path)

    if not os.path.exists(pip_path):
        logging.error("pip not found in the virtual environment.")
        sys.exit(1)

    logging.info(f"Python path: {python_path}")
    logging.info(f"pip path: {pip_path}")
    logging.info("Installing dependencies...")
    try:
        # Upgrade pip (optional)
        try:
            subprocess.run([pip_path, "install", "--upgrade", "pip"], check=True)
            logging.info("Pip upgraded successfully.")
        except subprocess.CalledProcessError as e:
            logging.warning(f"Failed to upgrade pip: {e}. Proceeding with existing pip version.")

        subprocess.run([pip_path, "install", "-r", os.path.join(PROJECT_DIR, REQUIREMENTS_FILE)], check=True)
        logging.info("Dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to install dependencies: {e}")
        sys.exit(1)

def create_csv_file():
    """Create an empty traffic_data.csv file in the project directory."""
    csv_file_path = os.path.join(PROJECT_DIR, CSV_FILE_NAME)
    if not os.path.exists(csv_file_path):
        logging.info(f"Creating empty {CSV_FILE_NAME} at {csv_file_path}...")
        try:
            with open(csv_file_path, 'w') as csv_file:
                pass  # Creates an empty file without writing any data
            logging.info(f"{CSV_FILE_NAME} created successfully.")
        except Exception as e:
            logging.error(f"Failed to create {CSV_FILE_NAME}: {e}")
            sys.exit(1)
    else:
        logging.info(f"{CSV_FILE_NAME} already exists. Skipping creation.")

def run_migrations():
    """Run makemigrations and migrate commands."""
    manage_py_dir = os.path.join(PROJECT_DIR, "ids_project")
    manage_py_path = os.path.join(manage_py_dir, "manage.py")
    venv_path = os.path.join(PROJECT_DIR, VENV_DIR)
    python_path, _ = get_virtualenv_paths(venv_path)

    logging.info(f"manage.py path: {manage_py_path}")
    logging.info(f"Python executable path: {python_path}")

    if not os.path.exists(manage_py_path):
        logging.error(f"manage.py not found at {manage_py_path}")
        sys.exit(1)

    if not os.path.exists(python_path):
        logging.error(f"Python executable not found at {python_path}")
        sys.exit(1)

    # Change working directory to manage_py_dir
    os.chdir(manage_py_dir)
    logging.info(f"Changed working directory to {os.getcwd()}")

    # Prepare environment variables
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([os.path.dirname(python_path), env.get("PATH", "")])
    logging.debug(f"Environment PATH: {env['PATH']}")

    # Run makemigrations
    logging.info("Running makemigrations...")
    command = [python_path, "manage.py", "makemigrations"]
    logging.info(f"Executing command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )
        logging.info(f"Makemigrations output:\n{result.stdout}")
        if result.stderr:
            logging.warning(f"Makemigrations warnings/errors:\n{result.stderr}")
    except Exception as e:
        logging.error(f"An error occurred during makemigrations: {e}")
        logging.error("Traceback:", exc_info=True)
        sys.exit(1)

    # Run migrate
    logging.info("Applying database migrations...")
    command = [python_path, "manage.py", "migrate"]
    logging.info(f"Executing command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )
        logging.info(f"Migrate output:\n{result.stdout}")
        if result.stderr:
            logging.warning(f"Migrate warnings/errors:\n{result.stderr}")
    except Exception as e:
        logging.error(f"An error occurred during migrate: {e}")
        logging.error("Traceback:", exc_info=True)
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

    if not os.path.exists(python_path):
        logging.error(f"Python executable not found at {python_path}")
        sys.exit(1)

    # Change working directory to manage_py_dir
    os.chdir(manage_py_dir)
    logging.info(f"Changed working directory to {os.getcwd()}")

    # Prepare environment variables
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([os.path.dirname(python_path), env.get("PATH", "")])
    logging.debug(f"Environment PATH: {env['PATH']}")

    logging.info("Starting Django development server...")
    command = [python_path, "manage.py", "runserver"]
    logging.info(f"Executing command: {' '.join(command)}")

    try:
        subprocess.run(
            command,
            check=True,
            env=env
        )
    except Exception as e:
        logging.error(f"An error occurred while running the server: {e}")
        logging.error("Traceback:", exc_info=True)
        sys.exit(1)

# -----------------------------
# Main Execution Block
# -----------------------------
if __name__ == "__main__":
    try:
        logging.info("===== Starting the Setup Process =====")
        git_pull()
        setup_virtualenv()
        create_csv_file()
        run_migrations()
        run_django()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        logging.error("Traceback:", exc_info=True)
        sys.exit(1)
