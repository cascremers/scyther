#!/bin/sh
#
# Multi-protocol analysis
#
# given a list of input files, test them in parallel
# limit number of runs to 5

ulimit -v 100000
cat $* | ../src/scyther -m1 -a -r4 -l40 --summary
