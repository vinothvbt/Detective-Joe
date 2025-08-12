import sys
import os

if sys.prefix == sys.base_prefix:
    print("Warning: Not running inside a virtual environment. Please run 'source .venv/bin/activate' after running setup.sh.")
    exit(1)