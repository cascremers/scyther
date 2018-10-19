#!/bin/sh

make clean ; make 2>&1  |grep "warning: trampoline" > trampolines.out
cat trampolines.out
echo 
wc -l trampolines.out

