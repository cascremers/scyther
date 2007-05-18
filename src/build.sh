#!/bin/sh

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

