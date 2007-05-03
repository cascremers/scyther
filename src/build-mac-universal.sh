#!/bin/sh

# Default flags
CMFLAGS="-D CMAKE_BUILD_TYPE:STRING=Release"

# Make for ppc and intel, and combine into universal binary
cmake $CMFLAGS -D TARGETOS=MacPPC   . && make
cmake $CMFLAGS -D TARGETOS=MacIntel . && make
cmake $CMFLAGS                      . && make scyther-mac

# Copy to the correct locations
./copy2gui.sh

