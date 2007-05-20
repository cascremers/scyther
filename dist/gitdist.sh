#!/bin/sh
#
# Make a new distribution archive. Command line specification of the tag
#
# For now, just windows. Others will follow.
#
# Usage will be:
#
#   gitdist ARCH TAG
#
#   ARCH is any of
#
#	linux
#	w32
#	mac
#
# The tag is checked out of the current repository (so it should exist)
# and this is used to construct a archive with the binary of the
# selected architecture.

CURDIR=`pwd`
echo $CURDIR

ARCH="w32"
TAG="test"

DOCDIR=doc/manual
MANUAL=scyther-manual.pdf

DNAM="scyther-$TAG"
TMPDIR="/tmp"
RESDIR="$TMPDIR/$DNAM"
rm -rf $RESDIR

DESTDIR=$CURDIR

# Where is it going to? Note without extension, this will added later
ARCHNAME=scyther-$ARCH-$TAG
DESTFILE=$DESTDIR/$ARCHNAME


cd .. && git-archive --format=tar --prefix=$DNAM/ $TAG | (cd $TMPDIR && tar xf -)

ls $RESDIR

# Windows binary
cd $RESDIR/src

# Where is stuff going to
DESTDIR=$RESDIR/gui

# Prepare version.h with the correct flag (tag)
echo "#define SVNVERSION \"Unknown\"" >$RESDIR/src/version.h
echo "#define TAGVERSION \"$TAG\"" >>$RESDIR/src/version.h
echo "" >>$RESDIR/src/version.h

# Manual
cp $RESDIR/$DOCDIR/$MANUAL $DESTDIR

# Default flags
CMFLAGS="-D CMAKE_BUILD_TYPE:STRING=Release"
if [ $ARCH = "w32" ]
then
	BIN="scyther-w32.exe"
	cmake $CMFLAGS -D TARGETOS=Win32 . && make

elif [ $ARCH = "linux" ]
then
	BIN="scyther-linux"
	cmake $CMFLAGS . && make

elif [ $ARCH = "mac" ]
then
	# Make for ppc and intel, and combine into universal binary
	BIN="scyther-mac"
	cmake $CMFLAGS -D TARGETOS=MacPPC   . && make
	cmake $CMFLAGS -D TARGETOS=MacIntel . && make
	cmake $CMFLAGS                      . && make scyther-mac
else
	echo "Don't know this architecture $ARCH"
	exit
fi

BINDIR=$RESDIR/gui/Scyther/Bin
mkdir $BINDIR
cp $BIN $BINDIR

# Prepare tag for gui version
echo "SCYTHER_GUI_VERSION = \"$TAG\"" >$DESTDIR/Gui/Version.py

# Make archive out of the result
WORKNAME="scyther-$TAG"
cd $RESDIR
mv gui $WORKNAME

# Compress the result into an archive
if [ $ARCH = "w32" ]
then
	DESTARCH=$DESTFILE.zip
	rm -f $DESTARCH
	zip -r $DESTARCH $WORKNAME

elif [ $ARCH = "linux" || $ARCH = "mac" ]
then
	DESTARCH=$DESTFILE.tgz
	rm -f $DESTARCH
	tar zcvf $DESTARCH $WORKNAME
fi

# Remove the temporary working directory
rm -rf $RESDIR


