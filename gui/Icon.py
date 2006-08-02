#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx
import os.path

#---------------------------------------------------------------------------

""" Import scyther-gui components """
import Misc

#---------------------------------------------------------------------------

def ScytherIcon(window):
        """ Set a nice Scyther icon """
        iconfile = Misc.mypath("scyther-gui-32.ico")
        if os.path.isfile(iconfile):
            icon = wx.Icon(iconfile,wx.BITMAP_TYPE_ICO)
            window.SetIcon(icon)


