#!/bin/sh

cmake -DTARGETOS=Win32 .
make
cmake .
make
./copy2gui.sh

