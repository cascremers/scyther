#!/bin/sh

# Default flags
CMFLAGS="-D CMAKE_BUILD_TYPE:STRING=Release"

# Make for linux
cmake $CMFLAGS -D TARGETOS=Unix  . && make

echo
echo
echo "---------------------------------------------------------"
echo "Built the Linux binary"

# Copy to the correct location
cp scyther-linux ../gui/Scyther/

# bonus...
cp scyther-linux ~/bin

echo Copied the file to the gui/Scyther directory and \~/bin
echo "---------------------------------------------------------"

