#!/bin/sh

../scyther -d -p0 -m2 -t2 -r 2 <ns3-brutus.spdl >brutus-m2-t2-r2.out
../scyther -d -p0 -m2 -t2 -r 3 <ns3-brutus.spdl >brutus-m2-t2-r3.out
../scyther -d -p0 -m2 -t2 -r 4 <ns3-brutus.spdl >brutus-m2-t2-r4.out
../scyther -d -p0 -m2 -t2 -r 5 <ns3-brutus.spdl >brutus-m2-t2-r5.out
../scyther -d -p0 -m2 -t2 -r 6 <ns3-brutus.spdl >brutus-m2-t2-r6.out

../scyther -d -p0 -m2 -t1 -r 2 <ns3-brutus.spdl >brutus-m2-t1-r2.out
../scyther -d -p0 -m2 -t1 -r 3 <ns3-brutus.spdl >brutus-m2-t1-r3.out
../scyther -d -p0 -m2 -t1 -r 4 <ns3-brutus.spdl >brutus-m2-t1-r4.out
../scyther -d -p0 -m2 -t1 -r 5 <ns3-brutus.spdl >brutus-m2-t1-r5.out
