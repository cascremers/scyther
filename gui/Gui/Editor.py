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


#---------------------------------------------------------------------------

""" Import externals """
import wx
import string

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

def justNumbers(txt):
    for x in txt:
        if not x in string.digits:
            return False
    return True

def lineInError(txt):
    # First option: square braces
    x1 = txt.find("[")
    if x1 >= 0:
        x2 = txt.find("]")
        if x2 > x1:
            nrstring = txt[(x1+1):x2]
            if justNumbers(nrstring):
                return int(nrstring)
    # Alternative: ...line x
    pref = " line "
    i = txt.find(pref)
    if i >= 0:
        i = i + len(pref)
        j = i
        while txt[j] in string.digits:
            j = j+1
        if j > i:
            return int(txt[i:j])

    return None

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
        self.SetChanged(False)

    def SetText(self):
        pass

    def SetErrors(self,errors):
        pass

    def GetChanged(self):
        """
        Return true if file was changed
        """
        return self.savedtext != self.GetText()

    def SetChanged(self,nowchanged=False):
        """
        Set changed status
        """
        if nowchanged:
            self.savedtext = ""
        else:
            self.SetSaved()

    def SetSaved(self):
        self.savedtext = self.GetText()

    def SetOpened(self):
        self.SetSaved()

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

        # Set variable for error style
        self.errorstyle = 5
        self.control.StyleSetSpec(self.errorstyle, "fore:#FFFF0000,back:#FF0000")

    def GetText(self):
        return self.control.GetText()

    def SetText(self, txt):
        self.control.SetText(txt)

    def GetLineCount(self):
        """ Currently rather stupid, can probably be done more
        efficiently through some Scintilla function. """
        txt = self.GetText().splitlines()
        return len(txt)

    def SetErrorLine(self,line):
        """
        Currently this is BROKEN for include commands, as no file names
        are propagated. To minize the damage, we at least don't try to
        highlight non-existing names. In the long run of course
        propagation is the only way to handle this.
        """
        if line <= self.GetLineCount():
            if line > 0:
                line = line - 1     # Start at 0 in stc, but on screen count is 1
                pos = self.control.GetLineIndentPosition(line)
                last = self.control.GetLineEndPosition(line)
                self.control.StartStyling(pos)
                self.control.SetStyling(last-pos,self.errorstyle)

    def ClearErrors(self):
        self.control.ClearDocumentStyle()

    def SetErrors(self,errors):
        if errors:
            for el in errors:
                nr = lineInError(el)
                if nr:
                    self.SetErrorLine(nr)
        else:
            self.ClearErrors()

#---------------------------------------------------------------------------

