#!/bin/sh

set -e 

# Default flags
CMFLAGS="-D CMAKE_BUILD_TYPE:STRING=Release"

# Make for windows and linux
cmake $CMFLAGS -D TARGETOS=Win32 . && make

echo
echo
echo "---------------------------------------------------------"
echo "Built the Windows binary"

# Copy to the correct location
cp scyther-w32.exe ../gui/Scyther/

echo Copied the file to the gui/Scyther directory
echo "---------------------------------------------------------"

