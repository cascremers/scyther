#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx
import wx.html

#---------------------------------------------------------------------------

""" Import scyther-gui components """

#---------------------------------------------------------------------------

class AboutScyther(wx.Dialog):
    text = '''
<html>
<body bgcolor="#ffffff">
    <center>
        <h1>Scyther</h1>
        Version 1.0-beta 6
    </center>
<hr>
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
    http://people.inf.ethz.ch/cremersc/scyther/index.html
</p>
<p>
    Credits: Cas Cremers (Scyther theory, backend, and main GUI
    code), Gijs Hollestelle (Python wrapper for Scyther XML output).
</p>
<hr>
'''

    def __init__(self,parent):
        wx.Dialog.__init__(self, parent, -1, 'About Scyther',
                size=(400,300))
        html = wx.html.HtmlWindow(self)
        if "gtk2" in wx.PlatformInfo:
            html.SetStandardFonts()
        html.SetPage(self.text)
        button = wx.Button(self, wx.ID_OK, "Okay")

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(html, 1, wx.EXPAND|wx.ALL,5)
        sizer.Add(button,0,wx.ALIGN_CENTER|wx.ALL,5)

        self.SetSizer(sizer)
        self.Layout()

