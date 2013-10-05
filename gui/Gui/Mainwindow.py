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
import os.path

#---------------------------------------------------------------------------

""" Import scyther-gui components """
import Settingswindow
import Scytherthread
import Icon
import About
import Editor
import Preference

#---------------------------------------------------------------------------

""" Some constants """
ID_VERIFY = 100
ID_AUTOVERIFY = 101
ID_CHARACTERIZE = 102
ID_CHECK = 103

#---------------------------------------------------------------------------

def MainInitOnce():
    result = Preference.usePIL()    # Makes sure PIL is tested.

class MainWindow(wx.Frame):

    def __init__(self, opts, args):
        super(MainWindow, self).__init__(None, size=(600,800))

        self.opts = opts
        self.args = args

        self.dirname = os.path.abspath('.')

        MainInitOnce()

        self.filename = 'noname.spdl'
        self.filepath = ""

        self.load = False

        # test
        if opts.test:
            self.filename = 'scythergui-default.spdl'
            self.load = True

        # if there is an argument (file), we load it
        if len(args) > 0:
            filename = args[0]
            if filename != '' and os.path.isfile(filename):
                (self.dirname,self.filename) = os.path.split(filename)
                self.load = True

        Icon.ScytherIcon(self)

        self.CreateInteriorWindowComponents()
        self.CreateExteriorWindowComponents()

        aTable = wx.AcceleratorTable([
                                      (wx.ACCEL_CTRL, ord('Q'), wx.ID_EXIT),
                                      (wx.ACCEL_NORMAL, wx.WXK_F1,
                                          ID_VERIFY),
                                      (wx.ACCEL_NORMAL, wx.WXK_F2,
                                          ID_CHARACTERIZE),
                                      (wx.ACCEL_NORMAL, wx.WXK_F5, 
                                          ID_CHECK),
                                      (wx.ACCEL_NORMAL, wx.WXK_F6,
                                          ID_AUTOVERIFY),
                                      ])
        self.SetAcceleratorTable(aTable)

        self.claimlist = []
        self.pnglist = []

        #self.SetTitle(self.title) 

        self.firstCommand()

    def CreateInteriorWindowComponents(self):
        ''' Create "interior" window components. In this case it is just a
            simple multiline text control. '''

        ## Make zoom buttons
        #sizer = wx.BoxSizer(wx.VERTICAL)
        #buttons = wx.BoxSizer(wx.HORIZONTAL)
        #bt = wx.Button(self,ID_VERIFY)
        #buttons.Add(bt,0)
        #self.Bind(wx.EVT_BUTTON, self.OnVerify, bt)
        #bt = wx.Button(self,ID_CHARACTERIZE)
        #buttons.Add(bt,0)
        #self.Bind(wx.EVT_BUTTON, self.OnCharacterize, bt)
        #sizer.Add(buttons, 0, wx.ALIGN_LEFT)

        # Top: input
        self.top = wx.Notebook(self,-1)
        # Editor there
        self.editor = Editor.selectEditor(self.top)

        if self.load:
            textfile = open(os.path.join(self.dirname, self.filename), 'r')
            self.editor.SetText(textfile.read())
            if self.dirname != "":
                os.chdir(self.dirname)
            textfile.close()
            self.editor.SetOpened()

        self.top.AddPage(self.editor.control,"Protocol description")
        self.settings = Settingswindow.SettingsWindow(self.top,self)
        self.top.AddPage(self.settings,"Settings")

        #sizer.Add(self.top,1,wx.EXPAND,1)
        #self.SetSizer(sizer)

    def CreateExteriorWindowComponents(self):
        ''' Create "exterior" window components, such as menu and status
            bar. '''
        self.CreateMenus()
        self.SetTitle()

    def CreateMenu(self, bar, name, list):

        fileMenu = wx.Menu()
        for id, label, helpText, handler in list:
            if id == None:
                fileMenu.AppendSeparator()
            else:
                item = fileMenu.Append(id, label, helpText)
                self.Bind(wx.EVT_MENU, handler, item)
        bar.Append(fileMenu, name) # Add the fileMenu to the MenuBar


    def CreateMenus(self):
        menuBar = wx.MenuBar()
        self.CreateMenu(menuBar, '&File', [
             (wx.ID_OPEN, '&Open', 'Open a new file', self.OnOpen),
             (wx.ID_SAVE, '&Save', 'Save the current file', self.OnSave),
             (wx.ID_SAVEAS, 'Save &As', 'Save the file under a different name',
                self.OnSaveAs),
             (None, None, None, None),
             (wx.ID_EXIT, 'E&xit\tCTRL-Q', 'Terminate the program',
                 self.OnExit)])
        self.CreateMenu(menuBar, '&Verify',
             [(ID_VERIFY, '&Verify protocol\tF1','Verify the protocol in the buffer using Scyther',
                 self.OnVerify) ,
             (ID_CHARACTERIZE, '&Characterize roles\tF2','TODO' ,
                 self.OnCharacterize) ,
             (None, None, None, None),
             ### Disabled for now (given that it is not reliable enough yet)
             #(ID_CHECK, '&Check protocol\tF5','TODO',
             #    self.OnCheck) ,
             (ID_AUTOVERIFY, 'Verify &automatic claims\tF6','TODO',
                 self.OnAutoVerify) 
             ])
        self.CreateMenu(menuBar, '&Help',
            [(wx.ID_ABOUT, '&About', 'Information about this program',
                self.OnAbout) ])
        self.SetMenuBar(menuBar)  # Add the menuBar to the Frame


    def SetTitle(self):
        # MainWindow.SetTitle overrides wx.Frame.SetTitle, so we have to
        # call it using super:
        super(MainWindow, self).SetTitle('Scyther: %s'%self.filename)

    # Helper methods:

    def defaultFileDialogOptions(self):
        ''' Return a dictionary with file dialog options that can be
            used in both the save file dialog as well as in the open
            file dialog. '''
        return dict(message='Choose a file', defaultDir=self.dirname,
                    wildcard='*.spdl')

    def askUserForFilename(self, **dialogOptions):
        dialog = wx.FileDialog(self, **dialogOptions)
        if dialog.ShowModal() == wx.ID_OK:
            userProvidedFilename = True
            self.filepath = dialog.GetPath()
            (p1,p2) = os.path.split(self.filepath)
            self.dirname = p1
            self.filename = p2
            self.SetTitle() # Update the window title with the new filename
        else:
            userProvidedFilename = False
        dialog.Destroy()
        return userProvidedFilename

    # Are we dropping a changed file?
    
    def ConfirmLoss(self,text=None):
        """
        Try to drop the current file. If it was changed, try to save
        (as)

        Returns true after the user seems to be happy either way, false
        if we need to cancel this.
        """
        if self.editor.GetChanged():
            # File changed, we need to confirm this
            title = "Unsaved changes"
            if text:
                title = "%s - " + title
            txt = "The protocol file '%s' has been modified.\n\n" % (self.filename)
            txt = txt + "Do you want to"
            txt = txt + " save your changes (Yes)"
            txt = txt + " or"
            txt = txt + " discard them (No)"
            txt = txt + "?"
            dialog = wx.MessageDialog(self,txt,title,wx.YES_NO | wx.CANCEL | wx.ICON_EXCLAMATION)
            result = dialog.ShowModal()            
            dialog.Destroy()
            if result == wx.ID_NO:
                # Drop changes
                return True
            elif result == wx.ID_YES:
                # First save(as)!
                if self.OnSaveAs(None):
                    # Succeeded, we can continue with the operation
                    return True
                else:
                    # Save did not succeed
                    return False
            else:
                # Assume cancel (wx.ID_CANCEL) otherwise
                return False
        else:
            # File was not changed, so we can just proceed
            return True

    # Event handlers

    def OnAbout(self, event):
        dlg = About.AboutScyther(self)
        dlg.ShowModal()
        dlg.Destroy()

    def OnExit(self, event):
        if self.ConfirmLoss("Exit"):
            self.Close()  # Close the main window.
            return True
        return False

    def OnSave(self, event):
        textfile = open(os.path.join(self.dirname, self.filename), 'w')
        textfile.write(self.editor.GetText())
        textfile.close()
        self.editor.SetSaved()
        return True

    def OnOpen(self, event):
        if self.ConfirmLoss("Open"):
            if self.askUserForFilename(style=wx.OPEN,
                                       **self.defaultFileDialogOptions()):
                textfile = open(os.path.join(self.dirname, self.filename), 'r')
                self.editor.SetText(textfile.read())
                textfile.close()
                self.editor.SetOpened()
                return True
        return False

    def OnSaveAs(self, event):
        if self.askUserForFilename(defaultFile=self.filename, style=wx.SAVE,
                                   **self.defaultFileDialogOptions()):
            self.OnSave(event)
            os.chdir(self.dirname)
            return True
        return False

    def RunScyther(self, mode):
        # Clear errors before verification
        self.editor.SetErrors(None)
        # Verify spdl
        spdl = self.editor.GetText()
        s = Scytherthread.ScytherRun(self,mode,spdl,self.editor.SetErrors)

    def OnVerify(self, event):
        self.RunScyther("verify")

    def OnAutoVerify(self, event):
        self.RunScyther("autoverify")

    def OnCharacterize(self, event):
        self.RunScyther("characterize")

    def OnCheck(self, event):
        self.RunScyther("check")

    def firstCommand(self):
        if self.opts.command:
            # Trigger a command automatically
            self.Show(True)
            self.RunScyther(self.opts.command)
                

#---------------------------------------------------------------------------
# vim: set ts=4 sw=4 et list lcs=tab\:>-:
