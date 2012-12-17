# Make recurse into 'src' directory
.PHONY:	default clean

default:
	cd src; ./build.sh
	

clean:
	cd src; make clean; cd ..

