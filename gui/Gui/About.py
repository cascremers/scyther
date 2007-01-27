#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx
import wx.html
import os.path

#---------------------------------------------------------------------------

""" Import scyther-gui components """

#---------------------------------------------------------------------------

""" Globals """

basedir = ""

#---------------------------------------------------------------------------

class AboutScyther(wx.Dialog):
    def __init__(self,parent,mybasedir=None):
        self.text = '''
<html>
<body bgcolor="#ffffff">
    <img src="$SPLASH">
        <p align="right"><b>Scyther : $VERSION</b></p>
<p>
    <b>Scyther</b> is an automatic tool for the verification and
    falsification of security protocols.
</p>
<p>
    Scyther and Scyther GUI developed by
    Cas Cremers 2004-2007.
</p>
<p>
    For news and updates visit the Scyther pages at 
    <a target="_blank" href="http://people.inf.ethz.ch/cremersc/scyther/index.html">
    http://people.inf.ethz.ch/cremersc/scyther/index.html</a>
</p>
<p>
    Credits: Cas Cremers (Scyther theory, backend, and main GUI
    code), Gijs Hollestelle (Python parser for Scyther XML output).
</p>
        '''

        if mybasedir:
            basedir = mybasedir

        splashdir = os.path.join(basedir,"Images")
        splashimage = os.path.join(splashdir,"scyther-splash.png")
        self.text = self.text.replace("$SPLASH",splashimage)

        # version information
        self.text = self.text.replace("$VERSION", "1.0-beta6")

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
