#!/usr/bin/env python
import os
import sys
import webbrowser
from threading import Timer


def open_browser():
    webbrowser.open_new("http://127.0.0.1:8000")


def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ids_project.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    if len(sys.argv) > 1 and sys.argv[1] == "runserver":
        Timer(3, open_browser).start()

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
