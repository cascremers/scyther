#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx
import wx.lib.newevent
import os
import sys
import re
import threading
import StringIO

#---------------------------------------------------------------------------

""" Import scyther components """
import XMLReader

""" Import scyther-gui components """
import Tempfile
import Claim
import Preference
import Scyther

#---------------------------------------------------------------------------

""" Global declaration """
(UpdateAttackEvent, EVT_UPDATE_ATTACK) = wx.lib.newevent.NewEvent()
busy = threading.Semaphore()


#---------------------------------------------------------------------------

class ScytherThread(threading.Thread):
    # Override Thread's __init__ method to accept the parameters needed:
    def __init__ ( self, mainwin, spdl, details, verifywin ):

        self.mainwin = mainwin
        self.verifywin = verifywin
        self.spdl = spdl
        self.details = details

        self.claims = []

        threading.Thread.__init__ ( self )

    def run(self):

        evt = UpdateAttackEvent(status="Running Scyther...")
        wx.PostEvent(self.mainwin, evt)

        self.claimResults()

        # Results are done (claimstatus can be reported)
        evt = UpdateAttackEvent(status="Done.")
        wx.PostEvent(self.mainwin, evt)

        # Shoot down the verification window and let the RunScyther function handle the rest
        self.mainwin.verified = True
        self.verifywin.Destroy()

    def claimResults(self):
        """ Convert spdl to result (using Scyther)

        The list of claim goes back to self.mainwin.claims, which is a
        property of the main window
        """

        scyther = Scyther.Scyther()
        
        scyther.options = self.mainwin.settings.ScytherArguments()
        if sys.platform.startswith('win'):
            scyther.program = "c:\\Scyther.exe"
            if not os.path.isfile(scyther.program):
                print "I can't find the Scyther executable %s" % (scyther.program)

        scyther.setInput(self.spdl)
        self.mainwin.claims = scyther.verify()
        self.summary = str(scyther)


class AttackThread(threading.Thread):
    # Override Thread's __init__ method to accept the parameters needed:
    def __init__ ( self, mainwin, resultwin ):

        self.mainwin = mainwin
        self.resultwin = resultwin

        threading.Thread.__init__ ( self )

    def run(self):

        evt = UpdateAttackEvent(status="Generating attack graphs...")
        wx.PostEvent(self.mainwin, evt)

        # create the images in the background
        self.makeImages()

    def makeImages(self):
        """ create images """
        for cl in self.mainwin.claims:
            for attack in cl.attacks:
                self.makeImage(attack)

    def makeImage(self,attack):
        """ create image for this particular attack """

        (fd2,fpname2) = Tempfile.tempcleaned(".png")
        pw,pr = os.popen2("dot -Tpng -o%s" % (fpname2))
        pw.write(attack.scytherDot)
        pw.close()
        attack.pngfile = fpname2  # this is where the file name is stored

class VerificationWindow(wx.Dialog):
    def __init__(
            self, parent, ID, title, size=wx.DefaultSize, pos=wx.DefaultPosition, 
            style=wx.DEFAULT_DIALOG_STYLE
            ):

        # Instead of calling wx.Dialog.__init__ we precreate the dialog
        # so we can set an extra style that must be set before
        # creation, and then we create the GUI dialog using the Create
        # method.
        pre = wx.PreDialog()
        pre.SetExtraStyle(wx.DIALOG_EX_CONTEXTHELP)
        pre.Create(parent, ID, title, pos, size, style)

        # This next step is the most important, it turns this Python
        # object into the real wrapper of the dialog (instead of pre)
        # as far as the wxPython extension is concerned.
        self.PostCreate(pre)

        # Now continue with the normal construction of the dialog
        # contents
        sizer = wx.BoxSizer(wx.VERTICAL)

        label = wx.StaticText(self, -1, "This is a wx.Dialog")
        label.SetHelpText("This is the help text for the label")
        sizer.Add(label, 0, wx.ALIGN_CENTRE|wx.ALL, 5)

        box = wx.BoxSizer(wx.HORIZONTAL)

        label = wx.StaticText(self, -1, "Field #1:")
        label.SetHelpText("This is the help text for the label")
        box.Add(label, 0, wx.ALIGN_CENTRE|wx.ALL, 5)

        text = wx.TextCtrl(self, -1, "", size=(80,-1))
        text.SetHelpText("Here's some help text for field #1")
        box.Add(text, 1, wx.ALIGN_CENTRE|wx.ALL, 5)

        sizer.Add(box, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.ALL, 5)

        box = wx.BoxSizer(wx.HORIZONTAL)

        label = wx.StaticText(self, -1, "Field #2:")
        label.SetHelpText("This is the help text for the label")
        box.Add(label, 0, wx.ALIGN_CENTRE|wx.ALL, 5)

        text = wx.TextCtrl(self, -1, "", size=(80,-1))
        text.SetHelpText("Here's some help text for field #2")
        box.Add(text, 1, wx.ALIGN_CENTRE|wx.ALL, 5)

        sizer.Add(box, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.ALL, 5)

        line = wx.StaticLine(self, -1, size=(20,-1), style=wx.LI_HORIZONTAL)
        sizer.Add(line, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.RIGHT|wx.TOP, 5)

        btnsizer = wx.StdDialogButtonSizer()
        
        if wx.Platform != "__WXMSW__":
            btn = wx.ContextHelpButton(self)
            btnsizer.AddButton(btn)
        
        btn = wx.Button(self, wx.ID_OK)
        btn.SetHelpText("The OK button completes the dialog")
        btn.SetDefault()
        btnsizer.AddButton(btn)

        btn = wx.Button(self, wx.ID_CANCEL)
        btn.SetHelpText("The Cancel button cnacels the dialog. (Cool, huh?)")
        btnsizer.AddButton(btn)
        btnsizer.Realize()

        sizer.Add(btnsizer, 0, wx.ALIGN_CENTER_VERTICAL|wx.ALL, 5)

        self.SetSizer(sizer)
        sizer.Fit(self)

#---------------------------------------------------------------------------

class ResultWindow(wx.Dialog):
    def __init__(
            self, parent, ID, title, size=wx.DefaultSize, pos=wx.DefaultPosition, 
            style=wx.DEFAULT_DIALOG_STYLE
            ):

        # Instead of calling wx.Dialog.__init__ we precreate the dialog
        # so we can set an extra style that must be set before
        # creation, and then we create the GUI dialog using the Create
        # method.
        pre = wx.PreDialog()
        pre.SetExtraStyle(wx.DIALOG_EX_CONTEXTHELP)
        pre.Create(parent, ID, title, pos, size, style)

        # This next step is the most important, it turns this Python
        # object into the real wrapper of the dialog (instead of pre)
        # as far as the wxPython extension is concerned.
        self.PostCreate(pre)

        # Now continue with the normal construction of the dialog
        # contents
        sizer = wx.BoxSizer(wx.VERTICAL)

        label = wx.StaticText(self, -1, "This is a wx.Dialog")
        label.SetHelpText("This is the help text for the label")
        sizer.Add(label, 0, wx.ALIGN_CENTRE|wx.ALL, 5)

        box = wx.BoxSizer(wx.HORIZONTAL)

        label = wx.StaticText(self, -1, "Field #1:")
        label.SetHelpText("This is the help text for the label")
        box.Add(label, 0, wx.ALIGN_CENTRE|wx.ALL, 5)

        text = wx.TextCtrl(self, -1, "", size=(80,-1))
        text.SetHelpText("Here's some help text for field #1")
        box.Add(text, 1, wx.ALIGN_CENTRE|wx.ALL, 5)

        sizer.Add(box, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.ALL, 5)

        box = wx.BoxSizer(wx.HORIZONTAL)

        label = wx.StaticText(self, -1, "Field #2:")
        label.SetHelpText("This is the help text for the label")
        box.Add(label, 0, wx.ALIGN_CENTRE|wx.ALL, 5)

        text = wx.TextCtrl(self, -1, "", size=(80,-1))
        text.SetHelpText("Here's some help text for field #2")
        box.Add(text, 1, wx.ALIGN_CENTRE|wx.ALL, 5)

        sizer.Add(box, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.ALL, 5)

        line = wx.StaticLine(self, -1, size=(20,-1), style=wx.LI_HORIZONTAL)
        sizer.Add(line, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.RIGHT|wx.TOP, 5)

        btnsizer = wx.StdDialogButtonSizer()
        
        if wx.Platform != "__WXMSW__":
            btn = wx.ContextHelpButton(self)
            btnsizer.AddButton(btn)
        
        btn = wx.Button(self, wx.ID_OK)
        btn.SetHelpText("The OK button completes the dialog")
        btn.SetDefault()
        btnsizer.AddButton(btn)

        btn = wx.Button(self, wx.ID_CANCEL)
        btn.SetHelpText("The Cancel button cnacels the dialog. (Cool, huh?)")
        btnsizer.AddButton(btn)
        btnsizer.Realize()

        sizer.Add(btnsizer, 0, wx.ALIGN_CENTER_VERTICAL|wx.ALL, 5)

        self.SetSizer(sizer)
        sizer.Fit(self)

#---------------------------------------------------------------------------


def RunScyther(mainwin,mode):

    global busy

    if (busy.acquire(False)):

        # Verification window

        verifywin = VerificationWindow(mainwin,-1,mode)
        verifywin.CenterOnScreen()

        # start the thread
        
        mainwin.SetCursor(wx.StockCursor(wx.CURSOR_WAIT))

        mainwin.verified = False
        mainwin.settings.mode = mode
        t =  ScytherThread(mainwin,mainwin.control.GetValue(),"",verifywin)
        t.start()

        # start the window and show until something happens
        # if it terminates, this is a cancel, and should also kill the thread. (what happens to a spawned Scyther in that case?)
        # if the thread terminames, it should close the window normally, and we end up here as well.

        val = verifywin.ShowModal()
        verifywin.Destroy()
        # kill thread anyway
        del(t)

        # Cursor back to normal
        mainwin.SetCursor(wx.StockCursor(wx.CURSOR_ARROW))

        if mainwin.verified:
                # Great, we verified stuff, progress to the claim report
                print "We verified stuff, hooray"
                resultwin = ResultWindow(mainwin,-1,mode)
        
                t = AttackThread(mainwin,resultwin)
                t.start()

                resultwin.CenterOnScreen()
                val = resultwin.ShowModal()
                resultwin.Destroy()

                # kill thread anyway
                del(t)

        else:
                # Verification was cancelled
                print "We wuz cancelled!"
        
        busy.release()




