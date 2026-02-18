#!/bin/sh

set -e

# Default flags
CMFLAGS="-D CMAKE_BUILD_TYPE:STRING=Release"

# Make for intel
cmake $CMFLAGS -D TARGETOS=MacArm . && make scyther-mac

echo 
echo
echo "---------------------------------------------------------"
echo "Built the Mac ARM binary"

# Copy to the correct locations
cp scyther-mac ../gui/Scyther/scyther-mac

echo Copied the files to their respective locations
echo "---------------------------------------------------------"
