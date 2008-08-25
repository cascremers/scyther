#!/bin/sh

PROTLIST=protocollist.txt
PROTUNIQ=protocollist-uniq.txt
ARGS="-r6 --partner-definition=1"

## Find the protocols including times, and full paths
find $HOME -name '*.spdl' -printf '%f\t%A@\t%p\n' | grep -v Backup | grep -v chain | sort -n -r >$PROTLIST

# Reverse sort, filter on uniq
cat $PROTLIST | awk '{ print $3,"\t",$1 }' | uniq -f1 | awk '{ print $1 }' >$PROTUNIQ

# Do the testing
echo "Virgil says: keep up the good work"
cat $PROTUNIQ | xargs -n 1 ./scyther-linux $ARGS --compromise=0 >compromise-0.txt
cat $PROTUNIQ | xargs -n 1 ./scyther-linux $ARGS --compromise=1 >compromise-1.txt
cat $PROTUNIQ | xargs -n 1 ./scyther-linux $ARGS --compromise=2 >compromise-2.txt

# Report
notify-cas.sh "New compromise tests done!"

