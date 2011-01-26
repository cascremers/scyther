#!/bin/sh
#
# batcher.sh
#
# usage: ./batcher.sh TEST_MPA_ARGUMENTS
#
# Tries to parallellize the jobs, and sends a mail afterwards

AWKSCRIPT=" { srand(); print int(1000000 * rand()) } "
RND=`echo | awk "$AWKSCRIPT"`

JOBNAME="test$RND"
JSONFILE="$PWD/$JOBNAME.json"
BATCHFILE="$PWD/$JOBNAME.sh"

echo $JOBNAME
echo $JSONFILE
echo $BATCHFILE

bsub -I -N -W 8:00 -J $JOBNAME ./test-mpa.py --pickle $JSONFILE $*
# Each verification has a time limit of 600 seconds = 10 minutes
# To fit in the one hour queue, that means 5 jobs maximum.
bsub -I -N -W 8:00 -J $JOBNAME -oo $BATCHFILE ./make-bsub.py $JSONFILE 5 -W 1:00 -J $JOBNAME
# Due to pending etc. the below may take a while.
sleep 10
bash $BATCHFILE
bsub -I -N -W 8:00 -J after$JOBNAME -w "ended($JOBNAME)" ./test-mpa.py $*


