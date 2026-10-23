# SR-20: gunicorn settings for heavy load.

import multiprocessing
import os

bind = os.environ.get("BIND", "0.0.0.0:8000")

worker_class = "gevent"  # many connections per worker, suits idle terminals
workers = int(os.environ.get("WEB_CONCURRENCY", multiprocessing.cpu_count() * 2 + 1))
worker_connections = 1000

backlog = 2048
timeout = 30
keepalive = 5
graceful_timeout = 30  # let in-flight requests (e.g. a ballot) finish on restart

max_requests = 10000  # recycle workers to limit slow memory growth
max_requests_jitter = 1000

accesslog = "-"
errorlog = "-"
loglevel = "info"