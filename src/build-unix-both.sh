#!/bin/sh

# Default flags
CMFLAGS="-D CMAKE_BUILD_TYPE:STRING=Release"

# Make for windows and linux
cmake $CMFLAGS -D TARGETOS=Win32 . && make
cmake $CMFLAGS                   . && make

# Copy to the correct locations
./copy2gui.sh

