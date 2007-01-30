#!/usr/bin/python

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

#---------------------------------------------------------------------------

""" Some constants """
ID_VERIFY = 100
ID_AUTOVERIFY = 101
ID_STATESPACE = 102
ID_CHECK = 103

#---------------------------------------------------------------------------

class MainWindow(wx.Frame):

    def __init__(self, opts, args):
        super(MainWindow, self).__init__(None, size=(600,800))

        self.opts = opts
        self.args = args

        self.dirname = os.path.abspath('.')

        self.filename = 'noname.spdl'
        self.load = False

        # test
        if opts.test:
            self.filename = 'scythergui-default.spdl'
            self.load = True

        # if there is an argument (file), we load it
        if len(args) > 0:
            filename = args[0]
            if filename != '' and os.path.isfile(filename):
                self.filename = filename
                self.load = True

        Icon.ScytherIcon(self)

        self.CreateInteriorWindowComponents()
        self.CreateExteriorWindowComponents()

        aTable = wx.AcceleratorTable([
                                      (wx.ACCEL_CTRL, ord('Q'), wx.ID_EXIT),
                                      (wx.ACCEL_NORMAL, wx.WXK_F1,
                                          ID_VERIFY),
                                      (wx.ACCEL_NORMAL, wx.WXK_F2,
                                          ID_STATESPACE),
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
        #bt = wx.Button(self,ID_STATESPACE)
        #buttons.Add(bt,0)
        #self.Bind(wx.EVT_BUTTON, self.OnStatespace, bt)
        #sizer.Add(buttons, 0, wx.ALIGN_LEFT)

        # Top: input
        self.top = wx.Notebook(self,-1)
        # Editor there
        self.editor = Editor.selectEditor(self.top)

        if self.load:
            textfile = open(os.path.join(self.dirname, self.filename), 'r')
            self.editor.SetText(textfile.read())
            os.chdir(self.dirname)
            textfile.close()
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
             (ID_STATESPACE, 'Generate &statespace\tF2','TODO' ,
                 self.OnStatespace) ,
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
            self.filename = dialog.GetFilename()
            self.dirname = dialog.GetDirectory()
            self.SetTitle() # Update the window title with the new filename
        else:
            userProvidedFilename = False
        dialog.Destroy()
        return userProvidedFilename

    # Event handlers:

    def OnAbout(self, event):
        dlg = About.AboutScyther(self)
        dlg.ShowModal()
        dlg.Destroy()

    def OnExit(self, event):
        self.Close()  # Close the main window.

    def OnSave(self, event):
        textfile = open(os.path.join(self.dirname, self.filename), 'w')
        textfile.write(self.editor.GetText())
        textfile.close()

    def OnOpen(self, event):
        if self.askUserForFilename(style=wx.OPEN,
                                   **self.defaultFileDialogOptions()):
            textfile = open(os.path.join(self.dirname, self.filename), 'r')
            self.editor.SetText(textfile.read())
            textfile.close()

    def OnSaveAs(self, event):
        if self.askUserForFilename(defaultFile=self.filename, style=wx.SAVE,
                                   **self.defaultFileDialogOptions()):
            self.OnSave(event)
            os.chdir(self.dirname)

    def RunScyther(self, mode):
        spdl = self.editor.GetText()
        s = Scytherthread.ScytherRun(self,mode,spdl)

    def OnVerify(self, event):
        self.RunScyther("verify")

    def OnAutoVerify(self, event):
        self.RunScyther("autoverify")

    def OnStatespace(self, event):
        self.RunScyther("statespace")

    def OnCheck(self, event):
        self.RunScyther("check")

    def firstCommand(self):
        if self.opts.command:
            # Trigger a command automatically
            self.Show(True)
            self.RunScyther(self.opts.command)
                

#---------------------------------------------------------------------------

