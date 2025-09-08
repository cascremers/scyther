#!/bin/sh

# Store version number in version.h
./describe-version.py

# Different choice if on Darwin
PLATFORM=`uname`
echo "Platform: $PLATFORM"

if [ "$PLATFORM" = "Darwin" ]; then
    ARCH=`arch`
    echo "Architecture: $ARCH"

    if [ "$ARCH" = "arm64" ]; then
        ./subbuild-mac-arm.sh
    else
	    ./subbuild-mac-intel.sh
	fi 
elif [ "$PLATFORM" = "Linux" ]; then
	# Build linux version
	./subbuild-unix-unix.sh
	
elif echo "$PLATFORM" | grep -q "MINGW64_NT"; then
   	# Build for mingW platforms
     echo "Building for MingW platform"
     ./subbuild-mingw-w64.sh
else
	echo "I don't know platform $PLATFORM, so I won't do anything"
fi
