import sys
import os

# Add backend folder to path so tests can find our modules
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.insert(0, backend_path)