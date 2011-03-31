#!/bin/sh

find lsf.* -maxdepth 0 -amin +11 -print -delete 2>&1


