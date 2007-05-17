#!/bin/sh
#
# The big unifying build script, which builds all binaries it can on a
# given platform.
#
# Effectively, if this script is run both on Darwin and Linux systems,
# all binaries can be constructed.

PLATFORM=`uname`
echo $PLATFORM
if [ "$PLATFORM" = "Darwin" ]
then
	./subbuild-mac-universal.sh
else
	if [ "$PLATFORM" = "Linux" ]
	then
		./subbuild-unix-both.sh
	else
		echo "I don't know platform $PLATFORM, so I won't do anything"
	fi
fi

