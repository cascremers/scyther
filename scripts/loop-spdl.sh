#!/bin/sh
#
# Script to iterate over all .spdl files
#
# Usage:
# 
#   loop-spdl.sh command_to_iterate
#
CMD=$*

find .. -name '*.spdl' | xargs -n 1 $CMD

