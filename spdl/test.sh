#!/bin/sh

../src/scyther -d -p0 -t4 -r 2 <ns3-brutus.spdl >brutus-t4-r2.out
../src/scyther -d -p0 -t4 -r 3 <ns3-brutus.spdl >brutus-t4-r3.out
../src/scyther -d -p0 -t4 -r 4 <ns3-brutus.spdl >brutus-t4-r4.out
../src/scyther -d -p0 -t4 -r 5 <ns3-brutus.spdl >brutus-t4-r5.out
../src/scyther -d -p0 -t4 -r 6 <ns3-brutus.spdl >brutus-t4-r6.out

../src/scyther -d -p0 -t2 -r 2 <ns3-brutus.spdl >brutus-t2-r2.out
../src/scyther -d -p0 -t2 -r 3 <ns3-brutus.spdl >brutus-t2-r3.out
../src/scyther -d -p0 -t2 -r 4 <ns3-brutus.spdl >brutus-t2-r4.out
../src/scyther -d -p0 -t2 -r 5 <ns3-brutus.spdl >brutus-t2-r5.out
../src/scyther -d -p0 -t2 -r 6 <ns3-brutus.spdl >brutus-t2-r6.out

../src/scyther -d -p0 -t1 -r 2 <ns3-brutus.spdl >brutus-t1-r2.out
../src/scyther -d -p0 -t1 -r 3 <ns3-brutus.spdl >brutus-t1-r3.out
../src/scyther -d -p0 -t1 -r 4 <ns3-brutus.spdl >brutus-t1-r4.out
../src/scyther -d -p0 -t1 -r 5 <ns3-brutus.spdl >brutus-t1-r5.out
