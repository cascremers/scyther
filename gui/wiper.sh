#!/bin/sh
#
# Wipe Brutus artefacts.
#
# Run as 'watch -n 10 ./wiper.sh'

find lsf.* -maxdepth 0 -amin +11 -print -delete 2>&1


