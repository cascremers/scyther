#!/bin/sh

cmake -DTARGETOS=MacPPC   . && make
cmake -DTARGETOS=MacIntel . && make
cmake . && make scyther-mac
./copy2gui.sh

