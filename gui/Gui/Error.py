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
import sys

#---------------------------------------------------------------------------

""" Import scyther-gui components """

#---------------------------------------------------------------------------

class PILError (Exception):
    pass

class NoAttackError(Exception):
    pass

#---------------------------------------------------------------------------

def ShowAndReturn(text):
    title = "Error"
    dlg = wx.MessageDialog(None, text, title, wx.ID_OK | wx.ICON_ERROR)
    result = dlg.ShowModal()
    dlg.Destroy()

def ShowAndExit(text):
    ShowAndReturn(text)
    sys.exit()

