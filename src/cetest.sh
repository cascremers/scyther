#!/bin/sh
#
# Test conform ce stuff.
#
./scyther -r6 $* <spdl/bkepk-ce.spdl
./scyther -r7 $* <spdl/bkepk-ce.spdl | tail -n 1
./scyther -r8 $* <spdl/bkepk-ce.spdl | tail -n 1
./scyther -r7 $* <spdl/bkepk-ce2.spdl | tail -n 1
./scyther -r8 $* <spdl/bkepk-ce2.spdl | tail -n 1
./scyther -r9 $* <spdl/bkepk-ce2.spdl | tail -n 1
