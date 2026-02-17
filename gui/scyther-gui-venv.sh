#!/usr/bin/env sh
#
# Scyther : An automatic verifier for security protocol.
# Copyright (C) 2007-2025 Cas Cremers
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# This script sets up a virtual environment with wxPython if it's not already available

# Change to the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

# Check if wxPython is already available in the system Python
if python3 -c "import wx; assert wx.VERSION >= (4, 0, 0)" 2>/dev/null; then
    echo "wxPython 4.0+ already installed in system Python, using it directly..."
    exec ./scyther-gui.py "$@"
fi

# Check if venv exists and has wxPython installed
if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/python3" ]; then
    # Venv exists, check if wxPython is installed in it
    if "$VENV_DIR/bin/python3" -c "import wx; assert wx.VERSION >= (4, 0, 0)" 2>/dev/null; then
        echo "Using existing virtual environment with wxPython..."
        source "$VENV_DIR/bin/activate"
        ./scyther-gui.py "$@"
        deactivate
        exit 0
    else
        echo "Virtual environment exists but wxPython is not properly installed, reinstalling..."
        rm -rf "$VENV_DIR"
    fi
fi

# Create new venv and install dependencies
echo "Creating virtual environment and installing wxPython..."
echo "This may take a few minutes on first run..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Install from requirements.txt if it exists, otherwise install wxpython directly
if [ -f "requirements.txt" ]; then
    pip3 install --quiet -r requirements.txt
else
    pip3 install --quiet wxpython
fi

echo "Setup complete! Starting Scyther GUI..."
./scyther-gui.py "$@"
deactivate