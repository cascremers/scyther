#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx

# Use Scintilla editor?
useStc = True       # It looks nicer!
#useStc = False      # It is sometimes buggy, claims the internet

# Test Scintilla and if it fails, get rid of it
if useStc:
    try:
        from wx.stc import *
    except:
        useStc = False

#---------------------------------------------------------------------------

""" Import scyther-gui components """

#---------------------------------------------------------------------------

""" Some constants """

#---------------------------------------------------------------------------

def selectEditor(parent):
    """
    Pick an editor (Scintilla or default) and return the object.
    """
    if useStc:
        return EditorStc(parent)
    else:
        return EditorNormal(parent)

#---------------------------------------------------------------------------

class Editor(object):

    def __init__(self, parent):
        # Empty start
        self.SetText("")

#---------------------------------------------------------------------------

class EditorNormal(Editor):

    def __init__(self, parent):
        self.control = wx.TextCtrl(parent, style=wx.TE_MULTILINE)

        # Call parent
        Editor.__init__(self,parent)

    def GetText(self):
        return self.control.GetValue()

    def SetText(self, txt):
        self.control.SetValue(txt)

#---------------------------------------------------------------------------

class EditorStc(Editor):

    def __init__(self, parent):
        # Scintilla layout with line numbers
        self.control = StyledTextCtrl(parent)
        self.control.SetMarginType(1, STC_MARGIN_NUMBER)
        self.control.SetMarginWidth(1, 30)

        # Call parent
        Editor.__init__(self,parent)

    def GetText(self):
        return self.control.GetText()

    def SetText(self, txt):
        self.control.SetText(txt)

#---------------------------------------------------------------------------

