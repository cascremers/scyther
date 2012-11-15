#!/bin/sh

FILES="$*"
EXT="pp"
#OUT=.
OUT=pp-results

if [ -n "$FILES" ]; then
	for file in $FILES;
	do
		if [ "$file" = "*.$EXT.*" ]; then
			echo "skipping $file"
		else
			echo "preprocessing $file"
			cpp $file | sed -e '/^(\#.*)*$/d' > $OUT/${file%%.*}.$EXT.spdl
		fi
	done
else
	printf "Usage: %s: file...\n" $(basename $0) >&2 
	exit 1
fi
