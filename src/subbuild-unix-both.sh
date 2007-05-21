#!/bin/sh

# Default flags
CMFLAGS="-D CMAKE_BUILD_TYPE:STRING=Release"

# Make for windows and linux
cmake $CMFLAGS -D TARGETOS=Win32 . && make
cmake $CMFLAGS                   . && make

echo
echo
echo "---------------------------------------------------------"
echo "Built the Linux and Windows binaries"

# Copy to the correct locations
cp scyther-linux ../gui/Scyther/
cp scyther-w32.exe ../gui/Scyther/

# bonus...
cp scyther-linux ~/bin

echo Copied the files to their respective locations and \~/bin
echo "---------------------------------------------------------"

