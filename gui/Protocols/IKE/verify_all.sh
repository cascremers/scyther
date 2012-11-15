#!/bin/bash

if [ -n "$*" ]; then
	FILES="$*"
	./verify.sh -i -r 4 -l 1 -u 3 -e remote $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m int $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m ca $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m afc $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m af $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m br $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m bri $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m ckw $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m ckwi $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m ck $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m cki $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m eck1 $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m eck1i $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m eck2 $FILES
	./verify.sh -i -r 4 -l 1 -u 3 -e remote -m eck2i $FILES
fi
