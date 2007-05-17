#!/bin/sh
#
# Arguments:
#
# svnversion executable path
#

SVNVERSION=`svnversion`
TAGVERSION=`awk 'BEGIN { FS="\""; } { print $2; }' ../gui/Gui/Version.py`

echo $SVNVERSION
echo $TAGVERSION

# Fix svnversion information
echo "#define SVNVERSION \"$SVNVERSION\"" >version.h
# Fix version tag
echo "#define TAGVERSION \"$TAGVERSION\"" >>version.h


