#!/bin/bash

TMP1="trampolines-raw.out"
TMP2="trampolines.out"

make clean ; make 2>$TMP1
cat $TMP1 | grep "warning: trampoline" | sort -u > $TMP2
cat $TMP2
echo 
wc -l $TMP2

