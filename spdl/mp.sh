#!/bin/sh
#
# Multi-protocol analysis
#
# given a list of input files, test them in parallel
# limit number of runs to 5

ulimit -v 100000
cat $* | ../src/scyther -a -r3 --summary
