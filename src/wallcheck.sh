#!/bin/sh
#
# Make log for all errors
#
scons -c; scons debug=yes 2>errorlog.txt


