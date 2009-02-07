#!/usr/bin/python
"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2009 Cas Cremers

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
import sys
try:
    import wx
except ImportError:
    print """
ERROR:

Could not find the required [wxPython] package.
Please install this package in order to use the graphical user
interface of Scyther.
The [wxPython] packages can be found at http://www.wxpython.org/

Note that you can still use the Scyther binaries in the 'Scyther' directory.
    """
    sys.exit(1)
import os
from optparse import OptionParser, SUPPRESS_HELP

#---------------------------------------------------------------------------

""" Import scyther-gui components """
from Gui import About,Preference,Mainwindow,Misc
from Scyther import Scyther

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
    #parser.add_option("-c","--check",dest="command",default=None,action="store_const",const="check",
    #        help="Immediately check protocol (requires input file)")

    # License
    parser.add_option("-l","--license",dest="license",default=False,action="store_const",const=True,
            help="Show license")

    # no-splash
    parser.add_option("-N","--no-splash",dest="splashscreen",default=True,action="store_const",const=False,
            help="Do not show the splash screen")

    # misc debug etc (not shown in the --help output)
    parser.add_option("","--test",dest="test",default=False,action="store_true",
            help=SUPPRESS_HELP)

    return parser.parse_args()

#---------------------------------------------------------------------------

class MySplashScreen(wx.SplashScreen):
    def __init__(self,basedir):
        path = os.path.join(basedir,"Images")
        image = os.path.join(path,"scyther-splash.png")
        bmp = wx.Image(image).ConvertToBitmap()
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

def isSplashNeeded(opts):
    if not opts.command:
        if opts.splashscreen and not (Preference.get('splashscreen') in ['false','off','disable','0']):
            return True
    return False

#---------------------------------------------------------------------------

class ScytherApp(wx.App):
    def OnInit(self):

        wx.GetApp().SetAppName("Scyther-gui")

        # Parse arguments
        basedir = os.path.abspath(os.path.dirname(sys.argv[0]))
        (opts,args) = parseArgs()

        # License option may abort here
        if opts.license:
            print Scyther.GetLicense()
            sys.exit(0)

        # Load preferences file
        Preference.init()

        # Init Scyther libs from preferences
        bindir = Preference.get("bindir",Scyther.getBinDir())
        Scyther.setBinDir(bindir)

        #"""
        #Create and show the splash screen.  It will then create and show
        #the main frame when it is time to do so.
        #
        #The splash screen is disabled for automatic commands, and also
        #by a setting in the preferences file.
        #"""
        #if isSplashNeeded(opts):
        #    splash = MySplashScreen(basedir)
        #    splash.Show()

        self.mainWindow = Mainwindow.MainWindow(opts,args)
        self.SetTopWindow(self.mainWindow)
        self.mainWindow.Show()

        if isSplashNeeded(opts):
            dlg = About.AboutScyther(self.mainWindow,basedir)
            dlg.ShowModal()
            dlg.Destroy()

        return True

    def OnExit(self):
        """ Tear down """


#---------------------------------------------------------------------------


if __name__ == '__main__':
    scythergui = ScytherApp()
    scythergui.MainLoop()

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
