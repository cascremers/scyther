#!/usr/bin/python

import wx

class App(wx.App):

    def OnInit(self):
        frame = wx.Frame(parent=None, title='Bare')
        frame.Show(1)
        return True

app = App()
app.MainLoop()

