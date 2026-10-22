# SR-20: gunicorn settings for running the app under heavy load.
#
# gunicorn only runs on Linux or macOS (on Windows use WSL). Start it from the
# backend folder:
#       cd backend
#       gunicorn -c ../gunicorn.conf.py app:app
# CHECK: "app:app" means the file app.py with a variable called app in it.
#
# Capacity maths (this is a calculation, not a measurement):
#   connections per server = workers x worker_connections
#   e.g. an 8 core server: 17 workers x 1000 = 17,000 connections
#   3 such servers behind nginx = 51,000, which covers the 40,000 target.
#
# Limitation: SQLite lets only one writer in at a time. For a real election
# the database would be PostgreSQL with a connection pool.
import multiprocessing
import os

bind = os.environ.get("BIND", "0.0.0.0:8000")

# gevent workers handle lots of connections each, which suits terminals that
# sit idle between actions. normal sync workers would handle one at a time.
worker_class = "gevent"
workers = int(os.environ.get("WEB_CONCURRENCY", multiprocessing.cpu_count() * 2 + 1))
worker_connections = 1000

backlog = 2048  # how many connections can queue up while workers are busy
timeout = 30  # restart a worker that is stuck for 30 seconds
keepalive = 5  # keep a connection open 5 seconds so terminals can reuse it

# restart workers now and then so a slow memory leak can't build up forever
max_requests = 10000
max_requests_jitter = 1000

accesslog = "-"
errorlog = "-"
loglevel = "info"