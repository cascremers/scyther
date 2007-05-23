#!/bin/sh

# Check whether the tag exists
TAG=$1
if [ "x$TAG" != "x" ]
then
	FOUND=`git-tag -l $TAG`
	if [ "x$TAG" = "x$FOUND" ]
	then
		echo "Tag $TAG found."
	else
		TAG=""
	fi
fi

if [ "x$TAG" = "x" ]
then
	echo
	echo "Scyther binary distribution generator."
	echo
	echo "  Usage: $0 <tag>"
	echo
	echo "Don't know tag $TAG, please select one from below:"
	git-tag -l
	exit
fi

# Determine system and build accordingly
OS=`uname -s`
if [ "x$OS" = "xDarwin" ]
then
	./gitdist.sh mac $TAG
elif [ "x$OS" = "xLinux" ]
then
	./gitdist.sh linux $TAG
	./gitdist.sh w32 $TAG
else
	echo "Don't know architecture $OS, where am I?"
	exit
fi

