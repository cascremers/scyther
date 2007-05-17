#!/bin/sh
# 
# Indent any changed files, ending in .c or .h
#
# TODO: Needs to be rewritten as svn of course is no longer used.
#
svn st | grep "^[MA].*\.[ch]$"| awk '{print $2}' | xargs indent
