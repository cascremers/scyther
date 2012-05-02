#!/bin/sh

# Store version number in version.h
./describe-version.py

# Different choice if on Darwin
PLATFORM=`uname`
echo $PLATFORM
if [ "$PLATFORM" = "Darwin" ]
then
	./subbuild-mac-universal.sh
else
	if [ "$PLATFORM" = "Linux" ]
	then
		# Build both versions
		./subbuild-unix-both.sh
	else
		echo "I don't know platform $PLATFORM, so I won't do anything"
	fi
fi

