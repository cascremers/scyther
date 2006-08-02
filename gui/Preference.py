#!/usr/bin/python

"""
    Preferences window and logic for saving and loading such things.
    Thus, some default things can be set here.

    init    loads stuff
    save    save the settings after some changes
    set(k,v)
    get(k)

    Currently used:

    match
    maxruns
    scyther
    scytheroptions
"""

#---------------------------------------------------------------------------

""" Import externals """

import wx
import os.path
import sys
from time import localtime,strftime

#---------------------------------------------------------------------------

""" Import scyther-gui components """

#---------------------------------------------------------------------------

""" Globals """

""" Locations of preferences. The last one is supposedly writable. """
prefname = "scythergui-config"
preflocs = []

#---------------------------------------------------------------------------

class Preferences(dict):

    def parse(self,line):
        line = line.strip()

        """ Skip comments """
        if not line.startswith("#"):
            split = line.find("=")
            if split != -1:
                key = line[:split].strip()
                data = line[(split+1):]
                self[key] = data.decode("string_escape")
                print "Read %s=%s" % (key,self[key])

    def load(self,file=""):
        if file == None:
            self["test1"] = "Dit is met een ' en een \", en dan\nde eerste dinges"
            self["test2"] = "En dit de tweede"
        elif file == "":
            """
            Test default locations
            """
            for f in preflocs:
                self.load(os.path.join(f,prefname))

        else:
            """
            Read this file
            """
            if os.path.isfile(file):
                fp = open(file,"r")
                for l in fp.readlines():
                    self.parse(l)
                fp.close()

    def show(self):
        print "Preferences:"
        for k in self.keys():
            print "%s=%s" % (k, self[k])

    def save(self):

        print "Saving preferences"
        prefpath = preflocs[-1]
        if not os.access(prefpath,os.W_OK):
            os.makedirs(prefpath)
        savename = os.path.join(prefpath,prefname)
        fp = open(savename,"w")

        fp.write("# Scyther-gui configuration file.\n#\n")
        date = strftime("%c",localtime())
        fp.write("# Last written on %s\n" % (date))
        fp.write("# Do not edit - any changes will be overwritten by Scyther-gui\n\n")

        l = list(self.keys())
        l.sort()
        for k in l:
            fp.write("%s=%s\n" % (k, self[k].encode("string_escape")))

        fp.close()

def init():
    """
        Load the preferences from a file, if possible
    """
    global prefs,preflocs

    sp = wx.StandardPaths.Get()
    confdir = sp.GetConfigDir()
    confdir += "/scyther"
    print confdir
    userconfdir = sp.GetUserConfigDir()
    userconfdir += "/"
    if sys.platform.startswith("lin"):
        userconfdir += "."
    userconfdir += "scyther"
    print userconfdir

    preflocs = [confdir,userconfdir]

    prefs = Preferences()
    prefs.load("")


def get(key,alt=None):
    global prefs

    if prefs.has_key(key):
        return prefs[key]
    else:
        return alt

def set(key,value):
    global prefs

    prefs[key]=value
    return

def save():
    global prefs

    prefs.save()


