#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import os
import tempfile
import atexit

#---------------------------------------------------------------------------

""" Local thing (can be done in numerous nicer ways) """
tempfiles = []

#---------------------------------------------------------------------------

def tempremove(tuple):
    (fd,fpname) = tuple
    #os.close(fd)
    os.remove(fpname)

def cleanupshop():
    global tempfiles

    for tuple in tempfiles:
        tempremove(tuple)

def tempcleaned(post=""):
    global tempfiles

    tuple = tempfile.mkstemp(post,"scyther_")
    tempfiles.append(tuple)
    return tuple

def tempcleanearly(tuple):
    global tempfiles

    tempfiles.remove(tuple)
    tempremove(tuple)

atexit.register(cleanupshop)
