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
import wx.html
import os.path

#---------------------------------------------------------------------------

""" Import scyther-gui components """

import Scyther

#---------------------------------------------------------------------------

""" Globals """

basedir = ""

#---------------------------------------------------------------------------

def setBaseDir(mybasedir):
        global basedir

        basedir = mybasedir

#---------------------------------------------------------------------------

class AboutScyther(wx.Dialog):
    def __init__(self,parent,mybasedir=None):

        from Version import SCYTHER_GUI_VERSION
        global basedir

        self.text = '''
<html>
<body bgcolor="#ffffff">
<img src="$SPLASH">
<h5 align="right">Scyther : $VERSION</h5>
<small>
    <p>
        <b>Scyther</b> is an automatic tool for the verification and
        falsification of security protocols.
    </p>
    <p>
        For news and updates visit the Scyther pages at 
        <a target="_blank" href="http://www.cs.ox.ac.uk/people/cas.cremers/scyther/index.html">
        http://www.cs.ox.ac.uk/people/cas.cremers/scyther/index.html</a>
    </p>
    <h5>License</h5>
    <p>
        Scyther : An automatic verifier for security protocols.<br>
        Copyright (C) 2007-2013 Cas Cremers
    </p>
    <p>
        This program is free software; you can redistribute it and/or
        modify it under the terms of the GNU General Public License
        as published by the Free Software Foundation; either version 2
        of the License, or (at your option) any later version.
    </p>
    <p>
        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.
    </p>
    <p>
        You should have received a copy of the GNU General Public License
        along with this program; if not, write to the Free Software
        Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
    </p>
    <h5>Backend version</h5>
    <p>
        $DETAILS
    </p>
    <h5>Credits</h5>
    <p>
        Cas Cremers (Scyther theory, backend, and main GUI
        code), Gijs Hollestelle (Python parser for Scyther XML output).
    </p>
</small>
        '''

        if mybasedir:
            basedir = mybasedir

        # Debugging output of some parameters

        splashdir = os.path.join(basedir,"Images")
        splashimage = os.path.join(splashdir,"scyther-splash.png")
        details_html = "Base directory: %s<br>\n" % (basedir)
        details_html += Scyther.Scyther.GetInfo(html=True)

        self.text = self.text.replace("$SPLASH",splashimage)
        self.text = self.text.replace("$DETAILS",details_html)

        # version information
        self.text = self.text.replace("$VERSION", SCYTHER_GUI_VERSION)

        wx.Dialog.__init__(self, parent, -1, 'About Scyther',
                size=(660,620))
        html = wx.html.HtmlWindow(self)
        #if "gtk2" in wx.PlatformInfo:
        #    html.SetStandardFonts()
        html.SetBorders(10)
        html.SetPage(self.text)
        button = wx.Button(self, wx.ID_OK, "Close window")

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(html, 1, wx.EXPAND|wx.ALL,0)
        sizer.Add(button,0,wx.ALIGN_CENTER|wx.ALL,5)

        self.SetSizer(sizer)
        self.Layout()

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
