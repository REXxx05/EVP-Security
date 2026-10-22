# Starts the app for load testing only, with the rate limiter switched off.
# Why: the limiter (SR-09) allows 100 requests/min per IP, and a load test
# sends everything from one IP, so it would just return 429 to every user.
# The limiter is tested separately; normal `python app.py` is untouched.
import os
import sys

# Make the backend folder importable (flat imports like `from extensions import db`)
BACKEND = os.path.join(os.path.dirname(__file__), "..", "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND))
os.chdir(os.path.abspath(BACKEND))

import app as app_module          # the teammate's app.py
from extensions import limiter

# app.py builds the Flask app inside create_app(), so call it
flask_app = getattr(app_module, "app", None) or app_module.create_app()

limiter.enabled = False           # load test only

if __name__ == "__main__":
    flask_app.run(host="127.0.0.1", port=5000, threaded=True, debug=False)
