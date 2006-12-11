#!/bin/sh
#------------------------------------------------------------------------------
#
#	makedist.sh
#
#	Make a Scyther distribution of the most recent revision.
#
#
#	A distribution is a directory
#
#	   scyther/
#	      - everything from ../gui
#	      SPORE/
#	        - spore files
#	      

#------------------------------------------------------------------------------
#
#	Parameters

RELEASE="scyther-1.0-beta5"

ARCHIVE="$RELEASE.tgz"
ZIPPED="$RELEASE.zip"

#	Creates a temporary subdirectory here.
TMPDIR=/tmp/scytherdist
WORKNAME=scyther

#	Repository
PROTROOT=https://svn.win.tue.nl/repos/scyther/trunk/spdl
SVNROOT=https://svn.win.tue.nl/repos/scyther/trunk
DOCROOT=https://svn.win.tue.nl/repos/scyther/trunk/manual

MANUAL=scyther-manual.pdf

#------------------------------------------------------------------------------
#
#	Derived things

WORKDIR=$TMPDIR/$WORKNAME
CURDIR=$PWD
DEST=$PWD/$ARCHIVE
ZIPDEST=$PWD/$ZIPPED
DOCDEST=$WORKDIR/doc

#------------------------------------------------------------------------------
#
#	Init

#	Remove old remnants and create a new directory
rm -f $DEST
rm -f $ZIPDEST
rm -rf $TMPDIR
mkdir $TMPDIR

#------------------------------------------------------------------------------
#
#	Collect required data and set up


#	Fill
svn export $SVNROOT/gui $WORKDIR
svn export $PROTROOT/SPORE $WORKDIR/SPORE

svn cat $DOCROOT/$MANUAL >$WORKDIR/$MANUAL

#------------------------------------------------------------------------------
#
#	Collected all needed data, finish up

#	Compress
cd $TMPDIR
tar zcvf $DEST $WORKNAME
zip -r $ZIPDEST $WORKNAME

#	Remove garbage
rm -rf $TMPDIR

#------------------------------------------------------------------------------
# Done.
