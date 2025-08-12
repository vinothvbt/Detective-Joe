#!/bin/bash
# Detective Joe v1.5 - Automated Setup Script
# Handles safe installation on Kali Linux and systems with PEP 668 restrictions

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    DETECTIVE JOE v1.5                       ║"
echo "║                 Automated Setup Script                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed or not in PATH"
    echo "   Please install Python 3 and try again"
    exit 1
fi

echo "🐍 Python 3 found: $(python3 --version)"

# Check if pip is available (needed for venv)
if ! python3 -m pip --version &> /dev/null; then
    echo "❌ Error: pip is not available"
    echo "   On Kali/Debian: sudo apt install python3-pip python3-venv"
    exit 1
fi

# Check for virtual environment
if [ ! -d ".venv" ]; then
    echo "📦 Creating Python virtual environment in .venv/"
    if ! python3 -m venv .venv; then
        echo "❌ Error: Failed to create virtual environment"
        echo "   On Kali/Debian: sudo apt install python3-venv"
        exit 1
    fi
    echo "✅ Virtual environment created successfully"
else
    echo "📦 Virtual environment already exists in .venv/"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source .venv/bin/activate

# Verify we're in the virtual environment
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "❌ Error: Failed to activate virtual environment"
    exit 1
fi

echo "✅ Virtual environment activated: $VIRTUAL_ENV"

# Install requirements
echo "📋 Installing requirements from requirements.txt..."
if [ -f "requirements.txt" ]; then
    if python3 -m pip install --timeout 30 --retries 3 -r requirements.txt; then
        echo "✅ Requirements installed successfully"
    else
        echo "❌ Error: Failed to install requirements"
        echo "   This might be due to network issues. Try running the script again."
        echo "   Or manually install: python3 -m pip install -r requirements.txt"
        exit 1
    fi
else
    echo "⚠️  Warning: requirements.txt not found, skipping pip install"
fi

echo ""
echo "🎉 Detective Joe v1.5 setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "   1. Activate the virtual environment: source .venv/bin/activate"
echo "   2. Run Detective Joe: python3 detectivejoe.py --help"
echo "   3. Start an investigation: python3 detectivejoe.py --interactive"
echo ""
echo "💡 Note: Always activate the virtual environment before running Detective Joe"
echo "   This ensures all dependencies are available and avoids PEP 668 issues."