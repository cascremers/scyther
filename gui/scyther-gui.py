#!/usr/bin/env python3
"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2025 Cas Cremers

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
# Ensure the script's directory is in sys.path so imports work from any location
import sys
import os
import pathlib

# Add the gui directory (where this script lives) to sys.path
script_dir = pathlib.Path(__file__).parent.resolve()
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

#---------------------------------------------------------------------------
# Try to get wxPython
try:
    import wx
except ImportError as err:
    from Scyther import Misc

    # Check if we are running in a virtual environment. If not, we can try to run inside it and install wxpython locally there.
    if sys.prefix == sys.base_prefix:
        # If these are the same, we are not in a venv.
        # Run wrapper script to call Scyther again, but now with venv wrapper.

        scriptname = 'scyther-gui-venv.sh'
        try:
            mypath = pathlib.Path(__file__).parent.resolve()
            venvscript = mypath / scriptname
        except:
            venvscript = scriptname

        os.execv(venvscript,sys.argv)
    
    errmsg = "Problem with importing the required [wxPython] package."

    if 'No module' in str(err):
        errmsg = """Could not find the required [wxPython] package.
Please install this package in order to use the graphical user
interface of Scyther.
The [wxPython] packages can be found at http://www.wxpython.org/

Ubuntu users: the wxPython packages are called 'python-wxgtk' followed by the
version number. This version of Scyther requires at least wxPython version 4.0."""
    
    Misc.panic("""
ERROR:

%s

Note that you can still use the Scyther binaries in the 'Scyther' directory.

The exact error was:
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------
    """ % (errmsg,err))


#---------------------------------------------------------------------------
global WXPYTHON4
global WXPYTHONINFREQ
WXPYTHON4 = False
WXPYTHONINFREQ = wx

try:
    import wx.adv

    WXPYTHON4 = True
    WXPYTHONINFREQ = wx.adv
except ImportError:
    Misc.panic("""
ERROR:

Found wxPython libraries, but they seem to be too old (pre-4.0 wxPython). This means you cannot use the graphical user interface. To fix this, please ensure that you have at least wxPython 4.0 installed such that it is loaded by the wx import of python3.

Note that you can currently still use the Scyther binaries in the 'Scyther' directory.
""")

""" import externals """
from argparse import ArgumentParser, SUPPRESS
from subprocess import *

#---------------------------------------------------------------------------

""" Import scyther-gui components """
from Scyther import Scyther,Misc
from Gui import About,Preference,Mainwindow

#---------------------------------------------------------------------------

def parseArgs():
    usage = "%(prog)s [options] [inputfile]"
    description = "scyther-gui is a graphical user interface for the scyther protocol verification tool."
    parser = ArgumentParser(usage=usage, description=description)

    # command
    parser.add_argument("-V", "--verify", dest="command", default=None, action="store_const", const="verify",
            help="Immediately verify the claims of the protocol (requires input file)")
    parser.add_argument("-s", "--state-space", dest="command", default=None, action="store_const", const="statespace",
            help="Immediately generate the complete characterization of the protocol (requires input file)")
    parser.add_argument("-a", "--auto-claims", dest="command", default=None, action="store_const", const="autoverify",
            help="Immediately verified protocol using default claims (requires input file)")

    # License
    parser.add_argument("-l", "--license", dest="license", default=False, action="store_const", const=True,
            help="Show license")

    # no-splash
    parser.add_argument("-N", "--no-splash", dest="splashscreen", default=True, action="store_const", const=False,
            help="Do not show the splash screen")

    # misc debug etc (not shown in the --help output)
    parser.add_argument("--test", dest="test", default=False, action="store_true",
            help=SUPPRESS)

    # Positional input files
    parser.add_argument("inputfiles", nargs="*")

    ns = parser.parse_args()
    args = ns.inputfiles
    del ns.inputfiles
    return (ns, args)

#---------------------------------------------------------------------------

class MySplashScreen(WXPYTHONINFREQ.SplashScreen):
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
        import os, inspect

        wx.GetApp().SetAppName("Scyther-gui")

        # Determine base directory (taking symbolic links into account)
        cmd_file = os.path.realpath(os.path.abspath(inspect.getfile( inspect.currentframe() )))
        basedir = os.path.split(cmd_file)[0]

        # Parse arguments
        (opts,args) = parseArgs()

        # License option may abort here
        if opts.license:
            print(Scyther.GetLicense())
            sys.exit(0)

        # Load preferences file
        Preference.init()

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

    #def OnExit(self):
    #    """ Tear down """
    #    # Currently unused, but ought to return the same integer as the base class if overridden.


#---------------------------------------------------------------------------

def CheckRequirements():
    """ Check for any required programs """

    """ We need 'dot', in the graphviz package """
    from Scyther import FindDot

    FindDot.findDot()   # If Graphviz is not found, this function will call panic to complain.

#---------------------------------------------------------------------------


if __name__ == '__main__':
    CheckRequirements()
    scythergui = ScytherApp()
    scythergui.MainLoop()

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
