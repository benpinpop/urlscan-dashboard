"""WSGI entrypoint for gunicorn: ``gunicorn -c gunicorn.conf.py wsgi:application``."""

from app import app as application

__all__ = ["application"]
