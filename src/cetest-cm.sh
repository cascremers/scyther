#!/bin/sh
#
# Test conform ce stuff, but our version
#
./scyther -r5 $* <spdl/bkepk.spdl
./scyther -r6 $* <spdl/bkepk.spdl | tail -n 1
