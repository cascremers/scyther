#!/bin/sh

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

