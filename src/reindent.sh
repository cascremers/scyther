#!/bin/sh
# 
# Indent any changed files, ending in .c or .h
#
svn st | grep "^[MA].*\.[ch]$"| awk '{print $2}' | xargs indent
