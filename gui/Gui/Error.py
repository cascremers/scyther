#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx
import sys

#---------------------------------------------------------------------------

""" Import scyther-gui components """

#---------------------------------------------------------------------------

def ShowAndExit(text):
    title = "Error"
    dlg = wx.MessageDialog(None, text, title, wx.ID_OK | wx.ICON_ERROR)
    result = dlg.ShowModal()
    dlg.Destroy()
    sys.exit()

