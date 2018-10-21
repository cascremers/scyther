#!/bin/sh

make clean ; make 2>&1  |grep "warning: trampoline" | sort -u > trampolines.out
cat trampolines.out
echo 
wc -l trampolines.out

