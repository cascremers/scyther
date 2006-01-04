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
#	      - readme.txt file with some indications from this
#	        directory.
#	      demo/
#	        - demo files
#	      SPORE/
#	        - spore files
#	      scyther/
#	        - scyther executable
#	      

#------------------------------------------------------------------------------
#
#	Parameters

ARCHIVE=scyther.tgz

#	Creates a temporary subdirectory here.
TMPDIR=/tmp/scytherdist
WORKNAME=scyther

#	Repository
SVNROOT=https://svn.win.tue.nl/repos/ecss/trunk/protocols/spdl

#------------------------------------------------------------------------------
#
#	Derived things

WORKDIR=$TMPDIR/$WORKNAME
CURDIR=$PWD
DEST=$PWD/$ARCHIVE

#------------------------------------------------------------------------------
#
#	Init

#	Remove old remnants and create a new directory
rm -f $DEST
rm -rf $TMPDIR
mkdir $TMPDIR

#	Create scyther/
mkdir $WORKDIR

#------------------------------------------------------------------------------
#
#	Collect required data and set up


#	Fill
svn export $SVNROOT/SPORE $WORKDIR/SPORE
svn export $SVNROOT/demo $WORKDIR/demo
svn export $SVNROOT/scyther $WORKDIR/scyther

#	Readme
cp readme.txt $WORKDIR

#------------------------------------------------------------------------------
#
#	Collected all needed data, finish up

#	Compress
cd $TMPDIR
tar zcvf $DEST $WORKNAME

#	Remove garbage
rm -rf $TMPDIR

#------------------------------------------------------------------------------
# Done.
