#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx
import sys

#---------------------------------------------------------------------------

""" Import scyther-gui components """
import Preference
import Mainwindow
import Misc

#---------------------------------------------------------------------------

class MySplashScreen(wx.SplashScreen):
    def __init__(self):
        bmp = wx.Image(Misc.mypath("images/scyther-splash.png")).ConvertToBitmap()
        wx.SplashScreen.__init__(self, bmp,
                                 wx.SPLASH_CENTRE_ON_SCREEN | wx.SPLASH_TIMEOUT,
                                 5000, None, -1)
        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.fc = wx.FutureCall(2000, self.ShowMain)

    def OnClose(self, evt):
        # Make sure the default handler runs too so this window gets
        # destroyed
        evt.Skip()
        self.Hide()
        
        # if the timer is still running then go ahead and show the
        # main frame now
        if self.fc.IsRunning():
            self.fc.Stop()
            self.ShowMain()


    def ShowMain(self):
        if self.fc.IsRunning():
            self.Raise()
        


class ScytherApp(wx.App):
    def OnInit(self):

        wx.GetApp().SetAppName("Scyther-gui")

        """
        Load preferences file
        """

        Preference.init()

        """
        Create and show the splash screen.  It will then create and show
        the main frame when it is time to do so.
        """


        splash = MySplashScreen()
        splash.Show()

        """ Build up """
        infile = ''
        args = sys.argv[1:]
        if len(args) > 0:
            if args[0] == 'test':
                infile = 'scythergui-default.spdl'
            else:
                infile = args[0]

        self.mainWindow = Mainwindow.MainWindow(infile)
        self.SetTopWindow(self.mainWindow)
        self.mainWindow.Show()

        return True

    def OnExit(self):
        """ Tear down """

if __name__ == '__main__':
    scythergui = ScytherApp()
    scythergui.MainLoop()


