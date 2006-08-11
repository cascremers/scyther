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
<center><table bgcolor = "#000000" width="100%" cellspacing="0"
cellpadding="0" border="1">
<tr>
    <td align="center"><h1>Scyther</h1></td>
</tr>
</table>
</center>
<p><b>Scyther</b> is cool.
        Scyther and Scyther GUI
        developed by Cas Cremers 2004-2006
        Credits: Gijs Hollestelle (Python wrapper around Scyther XML)
</p>
'''

    def __init__(self,parent):
        wx.Dialog.__init__(self, parent, -1, 'About Scyther',
                size=(440,400))
        html = wx.html.HtmlWindow(self)
        html.SetPage(self.text)
        button = wx.Button(self, wx.ID_OK, "Okay")

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(html, 1, wx.EXPAND|wx.ALL,5)
        sizer.Add(button,0,wx.ALIGN_CENTER|wx.ALL,5)

        self.SetSizer(sizer)
        self.Layout()

