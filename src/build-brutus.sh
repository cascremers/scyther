#!/bin/sh

# Brutus-specific setup
echo "If things don't work, try:"
echo
echo "  module load cmake"
echo "  module load gcc"
echo

# Store version number in version.h
./describe-version.py

# Default flags
CMFLAGS="-D CMAKE_BUILD_TYPE:STRING=Release"

# Make for windows and linux
cmake $CMFLAGS -D TARGETOS=Unix  . && make

echo
echo
echo "---------------------------------------------------------"
echo "Built the Linux binary for Brutus"

# Copy to the correct locations
cp scyther-linux ../gui/Scyther/
cp scyther-linux $HOME/bin/

