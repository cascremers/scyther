#!/bin/sh

./compareheuristics.py --program="../src/scyther" -m0 -b0 -p1
./compareheuristics.py --program="../src/scyther" -m1 -b0 -p1
./compareheuristics.py --program="../src/scyther" -m2 -b0 -p1
./compareheuristics.py --program="../src/scyther" -m0 -b1 -p1
./compareheuristics.py --program="../src/scyther" -m1 -b1 -p1
./compareheuristics.py --program="../src/scyther" -m2 -b1 -p1
./compareheuristics.py --program="../src/scyther" -m0 -b2 -p1
./compareheuristics.py --program="../src/scyther" -m1 -b2 -p1
./compareheuristics.py --program="../src/scyther" -m2 -b2 -p1

echo
echo "Done comparing nearly everything for the heuristics."
