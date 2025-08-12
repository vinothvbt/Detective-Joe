#!/bin/bash
set -e

# Check for venv, create if not exists
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
  echo "Created Python virtual environment in .venv/"
fi

# Activate venv and install requirements
source .venv/bin/activate
pip install -r requirements.txt

echo "Detective Joe is set up! To activate, run: source .venv/bin/activate"