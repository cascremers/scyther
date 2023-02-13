# Make recurse into 'src' directory
.PHONY:	default clean manual

default:
	cd src; ./build.sh

manual:
	cd manual; make

clean:
	cd src; make clean


