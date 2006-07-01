#!/bin/sh

rm boundtime?.txt
rm boundruns?.txt

\time -v -o boundtime1.txt ./test-all.sh scyther -r1 --plain >boundruns1.txt 
\time -v -o boundtime2.txt ./test-all.sh scyther -r2 --plain >boundruns2.txt 
\time -v -o boundtime3.txt ./test-all.sh scyther -r3 --plain >boundruns3.txt 
\time -v -o boundtime4.txt ./test-all.sh scyther -r4 --plain >boundruns4.txt 
\time -v -o boundtime5.txt ./test-all.sh scyther -r5 --plain >boundruns5.txt 
\time -v -o boundtime6.txt ./test-all.sh scyther -r6 --plain >boundruns6.txt 
\time -v -o boundtime7.txt ./test-all.sh scyther -r6 --plain >boundruns7.txt 
