"""Gunicorn settings.

Threads rather than extra processes: the app is I/O bound (it waits on
urlscan.io), and fewer processes keeps the in-memory rate limiter closer to a
single shared view of the world.
"""

import multiprocessing
import os

try:  # gunicorn reads this file before importing the app, so load .env here too
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

bind = f"{os.environ.get('HOST', '127.0.0.1')}:{os.environ.get('PORT', '8000')}"
workers = int(os.environ.get("WEB_CONCURRENCY", min(4, multiprocessing.cpu_count())))
threads = int(os.environ.get("WEB_THREADS", 4))
worker_class = "gthread"
timeout = 120
graceful_timeout = 30
keepalive = 5

accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info")

# Default access log format minus the query string, so a query someone pasted
# a key into by mistake cannot end up on disk.
access_log_format = '%(h)s "%(m)s %(U)s" %(s)s %(b)s %(D)sus "%(a)s"'
