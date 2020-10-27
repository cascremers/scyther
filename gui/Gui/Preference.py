#!/usr/bin/python
"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2013 Cas Cremers

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""


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
    scytheroptions
    bindir          where the scyther executables reside
    splashscreen    0/1
"""

#---------------------------------------------------------------------------

""" Import externals """

import wx
import os.path
import sys
from time import localtime,strftime

#---------------------------------------------------------------------------

""" Import scyther-gui components """
from . import Makeimage

#---------------------------------------------------------------------------

""" Globals """
# Do we have the Python Imaging library?
havePIL = True
testPILOkay = None
try:
    import Image
except ImportError:
    havePIL = False 

""" Locations of preferences. The last one is supposedly writable. """
prefname = "scythergui-config"
preflocs = []

#---------------------------------------------------------------------------

def usePIL():
    """
    Determine whether or not we should use the PIL library
    """
    global havePIL, testPILOkay

    if not havePIL:
        return False

    # Only if we have it, and it is windows.
    if not sys.platform.startswith("lin"):
        return False

    # Seems fine. But did we already test it?
    if testPILOkay != None:
        return testPILOkay

    # Test the usage
    testPILOkay = True
    testPILOkay = testPIL()
    return testPILOkay

def doNotUsePIL():
    """
    Disable
    """
    global havePIL

    havePIL = False


def testPIL():
    """
    Test whether PIL works as we want it.

    We generate a postscript file from a dot file, and see what happens.
    """

    # depends on PIL lib
    okay = True
    try:
        Makeimage.testImage()
        # PIL seems fine
    except:
        # PIL broke
        doNotUsePIL()
        okay = False

    return okay


#---------------------------------------------------------------------------

class Preferences(dict):

    def setDict(self,d):
        """
        Copy dict into self.
        """
        for x in list(d.keys()):
            self[x] = d[x]

    def parse(self,line):
        line = line.strip()

        """ Skip comments """
        if not line.startswith("#"):
            split = line.find("=")
            if split != -1:
                key = line[:split].strip()
                data = line[(split+1):]
                self[key] = data.decode("string_escape")
                #print "Read %s=%s" % (key,self[key])

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
        print("Preferences:")
        for k in list(self.keys()):
            print("%s=%s" % (k, self[k]))

    def save(self):

        print("Saving preferences")
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
    #print confdir
    userconfdir = sp.GetUserConfigDir()
    userconfdir += "/"
    if sys.platform.startswith("lin"):
        userconfdir += "."
    userconfdir += "scyther"
    #print userconfdir

    preflocs = [confdir,userconfdir]

    prefs = Preferences()
    prefs.load("")


def get(key,alt=None):
    global prefs

    if key in list(prefs.keys()):
        return prefs[key]
    else:
        return alt

def getkeys():
    global prefs

    return list(prefs.keys())

def set(key,value):
    global prefs

    prefs[key]=value
    return

def save():
    global prefs

    prefs.save()

#---------------------------------------------------------------------------
# vim: set ts=4 sw=4 et list lcs=tab\:>-:
