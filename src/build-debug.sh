#!/bin/sh

# Store version number in version.h
./describe-version.py

# Default flags
CMFLAGS="-D CMAKE_BUILD_TYPE:STRING=Debug"

# Make for linux
cmake $CMFLAGS                   . && make

echo
echo
echo "---------------------------------------------------------"
echo "Built the Linux binary"

# Copy to the correct location
cp scyther-linux ../gui/Scyther/

# bonus...
if [ -d ~/bin  ] ; then
  cp scyther-linux ~/bin/
fi

echo "Copied the file to the gui directory and \~/bin (if present)"
echo "---------------------------------------------------------"

