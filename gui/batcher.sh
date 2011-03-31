#!/bin/sh
#
# batcher.sh
#
# usage: ./batcher.sh TEST_MPA_ARGUMENTS
#
# Tries to parallellize the jobs, and sends a mail afterwards

echo "================================="
echo " Phase 0: Setup"
echo "================================="
AWKSCRIPT=" { srand(); print int(1000000 * rand()) } "
RND=`echo | awk "$AWKSCRIPT"`

JOBNAME="test$RND"
JSONFILE="$PWD/$JOBNAME.json"
BATCHFILE="$PWD/$JOBNAME.sh"

echo $JOBNAME
echo $JSONFILE
echo $BATCHFILE

echo "================================="
echo " Phase 1: generate jobs list"
echo "================================="
bsub -I -N -W 8:00 -J $JOBNAME ./test-mpa.py --pickle $JSONFILE $*

echo "================================="
echo " Phase 2a: precompute job outputs"
echo "================================="
# Each verification has a time limit of 600 seconds = 10 minutes
# To fit in the one hour queue, that means 5 jobs maximum.
bsub -I -N -W 8:00 -J $JOBNAME -oo $BATCHFILE ./make-bsub.py $JSONFILE 5 -W 1:00 -J $JOBNAME
# Due to pending etc. the below may take a while.
sleep 10
bash $BATCHFILE
echo "================================="
echo " Phase 2b: perfom actual job"
echo " (after precomputation is done"
echo "================================="
bsub -I -N -W 8:00 -J after$JOBNAME -w "ended($JOBNAME)" ./test-mpa.py $*


echo "================================="
echo " Done."
echo "================================="
