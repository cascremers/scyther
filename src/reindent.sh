#!/bin/sh
# 
# Indent any changed files, ending in .c or .h
#
svn st | grep "^M.*\.[ch]$"| awk '{print $2}' | xargs indent
