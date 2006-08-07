#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx
import sys
from optparse import OptionParser, SUPPRESS_HELP

#---------------------------------------------------------------------------

""" Import scyther-gui components """
import Preference
import Mainwindow
import Misc

#---------------------------------------------------------------------------

def parseArgs():
    usage = "usage: %s [options] [inputfile]" % sys.argv[0]
    description = "scyther-gui is a graphical user interface for the scyther protocol verification tool."
    parser = OptionParser(usage=usage,description=description)

    # command
    parser.add_option("-V","--verify",dest="command",default=None,action="store_const",const="verify",
            help="Immediately verify the claims of the protocol (requires input file)")
    parser.add_option("-s","--state-space",dest="command",default=None,action="store_const",const="statespace",
            help="Immediately generate the complete characterization of the protocol (requires input file)")
    parser.add_option("-a","--auto-claims",dest="command",default=None,action="store_const",const="autoverify",
            help="Immediately verified protocol using default claims (requires input file)")
    parser.add_option("-c","--check",dest="command",default=None,action="store_const",const="check",
            help="Immediately check protocol (requires input file)")

    # misc debug etc (not shown in the --help output)
    parser.add_option("","--test",dest="test",default=False,action="store_true",
            help=SUPPRESS_HELP)

    return parser.parse_args()

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
        

#---------------------------------------------------------------------------

class ScytherApp(wx.App):
    def OnInit(self):

        wx.GetApp().SetAppName("Scyther-gui")

        # Parse arguments
        (opts,args) = parseArgs()

        # Load preferences file
        Preference.init()

        """
        Create and show the splash screen.  It will then create and show
        the main frame when it is time to do so.
        
        The splash screen is disabled for automatic commands, and also
        by a setting in the preferences file.
        """
        if not opts.command:
            if not (Preference.get('splashscreen') in ['false','off','disable','0']):
                splash = MySplashScreen()
                splash.Show()

        self.mainWindow = Mainwindow.MainWindow(opts,args)
        self.SetTopWindow(self.mainWindow)
        self.mainWindow.Show()

        return True

    def OnExit(self):
        """ Tear down """

if __name__ == '__main__':
    scythergui = ScytherApp()
    scythergui.MainLoop()


