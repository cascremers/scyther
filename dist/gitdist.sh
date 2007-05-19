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
ARCH=w32
TAG="v1.0-beta7.1"

DOCDIR=doc/manual
MANUAL=scyther-manual.pdf
ZIPNAME=scyther-$ARCH-$TAG.zip

DNAM="scyther-$TAG"
TMPDIR="/tmp"
RESDIR="$TMPDIR/$DNAM"
rm -rf $RESDIR

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
# Make for windows and linux
cmake $CMFLAGS -D TARGETOS=Win32 . && make
#cmake $CMFLAGS                   . && make

cp scyther-w32.exe $RESDIR/gui/Scyther/Bin

# Prepare tag for gui version
echo "SCYTHER_GUI_VERSION = \"$TAG\"" >$DESTDIR/Gui/Version.py

# Make archive out of the result
WORKNAME="scyther-$TAG"
cd $RESDIR
mv gui $WORKNAME

zip -r ../$ZIPNAME $WORKNAME
rm -rf $RESDIR


