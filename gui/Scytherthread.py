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
import Attackwindow

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
            if cl.button:
                cl.button.Enable()

    def makeImage(self,attack):
        """ create image for this particular attack """

        (fd2,fpname2) = Tempfile.tempcleaned(".png")
        pw,pr = os.popen2("dot -Tpng -o%s" % (fpname2))
        pw.write(attack.scytherDot)
        pw.close()
        pr.close()
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

        label = wx.StaticText(self, -1, "Verifying protocol")
        sizer.Add(label, 0, wx.ALIGN_CENTRE|wx.ALL, 5)

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

class ResultWindow(wx.Frame):
    def __init__(
            self, mainwindow, ID, title, size=wx.DefaultSize, pos=wx.DefaultPosition, 
            style=wx.DEFAULT_DIALOG_STYLE
            ):

        self.mainwindow = mainwindow

        # Instead of calling wx.Dialog.__init__ we precreate the dialog
        # so we can set an extra style that must be set before
        # creation, and then we create the GUI dialog using the Create
        # method.
        pre = wx.PreDialog()
        pre.Create(mainwindow, ID, title, pos, size, style)

        # This next step is the most important, it turns this Python
        # object into the real wrapper of the dialog (instead of pre)
        # as far as the wxPython extension is concerned.
        self.PostCreate(pre)

        # Now continue with the normal construction of the dialog
        # contents
        sizer = wx.BoxSizer(wx.VERTICAL)

        # set up grid
        claims = mainwindow.claims
        self.grid = grid = wx.GridBagSizer(8,1+len(claims))

        grid.Add(wx.StaticText(self,-1,"Protocol "),(0,0))
        grid.Add(wx.StaticText(self,-1,"Role "),(0,1))
        grid.Add(wx.StaticText(self,-1,"Label "),(0,2))
        grid.Add(wx.StaticText(self,-1,"Claim type "),(0,3))
        grid.Add(wx.StaticText(self,-1,"Parameter "),(0,4))
        grid.Add(wx.StaticText(self,-1,"Status "),(0,5))
        grid.Add(wx.StaticText(self,-1,"View "),(0,6))


        lastprot = None
        lastrole = None
        for i in range(len(claims)-1,-1,-1):
            cl = claims[i]
            # we reverse the display order of the claims!
            y = len(claims)-i

            prot = str(cl.protocol)
            if prot != lastprot:
                grid.Add(wx.StaticText(self,-1,prot),(y,0))
                lastprot = prot
            role = str(cl.role)
            if role != lastrole:
                grid.Add(wx.StaticText(self,-1,role),(y,1))
                lastrole = role

            grid.Add(wx.StaticText(self,-1,str(cl.shortlabel)),(y,2))
            grid.Add(wx.StaticText(self,-1,str(cl.claimtype)),(y,3))
            grid.Add(wx.StaticText(self,-1,str(cl.parameter)),(y,4))
            if cl.okay:
                okay = "Ok"
            else:
                okay = "Fail"
            grid.Add(wx.StaticText(self,-1,okay),(y,5))

            # add view button (if needed)
            n = len(cl.attacks)
            if n > 0:
                # Aha, something to show
            
                blabel = "%i %s" % (n,cl.stateName(n))
                cl.button = wx.Button(self,-1,blabel)
                cl.button.Disable()
                grid.Add(cl.button,(y,6))
                self.Bind(wx.EVT_BUTTON, self.onViewButton,cl.button)
            else:
                cl.button = None

            # remark something about completeness
            remark = ""
            if not cl.complete:
                if n == 0:
                    # no attacks, no states within bounds
                    remark = "(within bounds)"
                else:
                    # some attacks/states within bounds
                    remark = "(at least, maybe more)"
            else:
                if n == 0:
                    # no attacks, no states
                    remark = "" 
                else:
                    # there exist n states/attacks (within any number of runs)
                    remark = "(exactly)"

            grid.Add(wx.StaticText(self,-1,remark),(y,7))
                
        sizer.Add(grid, 0,wx.ALIGN_CENTRE|wx.ALL,5)

        # separator
        line = wx.StaticLine(self, -1, size=(20,-1), style=wx.LI_HORIZONTAL)
        sizer.Add(line, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.RIGHT|wx.TOP, 5)

        btnsizer = wx.StdDialogButtonSizer()
        
        btn = wx.Button(self, wx.ID_OK)
        btn.SetHelpText("Close window")
        btn.SetDefault()
        self.Bind(wx.EVT_BUTTON,self.onCloseButton,btn)
        btnsizer.AddButton(btn)

        btnsizer.Realize()

        sizer.Add(btnsizer, 0, wx.ALIGN_CENTER_VERTICAL|wx.ALL|wx.ALIGN_RIGHT, 5)

        self.SetSizer(sizer)
        sizer.Fit(self)

    def onViewButton(self,evt):
        btn = evt.GetEventObject()
        (y,x) = self.grid.GetItemPosition(btn)
        n = len(self.mainwindow.claims)
        cln = n-y
        cl = self.mainwindow.claims[cln]
        w = Attackwindow.AttackWindow(cl)

    def onCloseButton(self,evt):
        del(self.thread)
        self.Destroy()

#---------------------------------------------------------------------------


def RunScyther(mainwin,mode):

    global busy

    if (busy.acquire(False)):

        # Verification window

        verifywin = VerificationWindow(mainwin,-1,mode)
        verifywin.CenterOnScreen()

        # start the thread
        
        verifywin.SetCursor(wx.StockCursor(wx.CURSOR_WAIT))

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
        verifywin.SetCursor(wx.StockCursor(wx.CURSOR_ARROW))

        if mainwin.verified:
                # Great, we verified stuff, progress to the claim report
                title = "Scyther results : %s" % mode
                resultwin = ResultWindow(mainwin,-1,title)
        
                t = AttackThread(mainwin,resultwin)
                t.start()

                resultwin.thread = t
                resultwin.CenterOnScreen()
                resultwin.Show(1)

        busy.release()




