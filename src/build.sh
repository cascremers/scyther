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
else
	if [ "$PLATFORM" = "Linux" ]; then
		# Build linux version
		./subbuild-unix-unix.sh
	else
		echo "I don't know platform $PLATFORM, so I won't do anything"
	fi
fi

