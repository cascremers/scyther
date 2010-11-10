#!/bin/sh
# 
# Indent any files ending in .c or .h
#
# Apparently unstable behaviour is possible; a stupid fix for my
# concrete problem was to always run it twice.
#
indent *.c *.h
indent *.c *.h

