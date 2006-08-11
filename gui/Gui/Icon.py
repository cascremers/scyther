#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx
import os.path
import sys

#---------------------------------------------------------------------------

""" Import scyther-gui components """
import Misc

#---------------------------------------------------------------------------

def ScytherIcon(window):
        """ Set a nice Scyther icon """
        basedir = os.path.abspath(os.path.dirname(sys.argv[0]))
        path = os.path.join(basedir,"Images")
        iconfile = Misc.mypath(os.path.join(path,"scyther-gui-32.ico"))
        if os.path.isfile(iconfile):
            icon = wx.Icon(iconfile,wx.BITMAP_TYPE_ICO)
            window.SetIcon(icon)


