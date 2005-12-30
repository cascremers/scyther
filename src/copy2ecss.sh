#!/bin/sh

SVNDIR=https://svn.win.tue.nl/repos/ecss/trunk/protocols/spdl/scyther
TMPDIR=/tmp/ecsslatesscyther
VERSIONFILE=$TMPDIR/version.txt
SCYTHER=$TMPDIR/scyther

rm -rf $TMPDIR
svn co $SVNDIR $TMPDIR
cp scyther $SCYTHER
$SCYTHER --version >$VERSIONFILE
cat $VERSIONFILE
svn commit --file $VERSIONFILE $SCYTHER

echo "Committed this version to the ECSS repository."
