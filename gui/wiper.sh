#!/bin/sh

clear

find lsf.* -maxdepth 0 -amin +11 -print0 -delete


