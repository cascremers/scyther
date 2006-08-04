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

        self.claimResults()

        # Results are done (claimstatus can be reported)

        # Shoot down the verification window and let the RunScyther function handle the rest
        self.mainwin.verified = True
        self.verifywin.Close()

    def claimResults(self):
        """ Convert spdl to result (using Scyther)

        The list of claim goes back to self.mainwin.claims, which is a
        property of the main window
        """

        scyther = Scyther.Scyther()
        
        scyther.options = self.mainwin.settings.ScytherArguments()
        if sys.platform.startswith('win'):
            """ Windows """
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

        # create the images in the background
        self.makeImages()

    def makeImages(self):
        """ create images """
        for cl in self.mainwin.claims:
            for attack in cl.attacks:
                self.makeImage(attack)
            if cl.button and len(cl.attacks) > 0:
                cl.button.Enable()

    def makeImage(self,attack):
        """ create image for this particular attack """

        (fd2,fpname2) = Tempfile.tempcleaned(".png")
        pw,pr = os.popen2("dot -Tpng -o%s" % (fpname2))
        pw.write(attack.scytherDot)
        pw.close()
        pr.close()
        attack.pngfile = fpname2  # this is where the file name is stored

#---------------------------------------------------------------------------

class VerificationWindow(wx.Dialog):
    def __init__(
            self, parent, ID, title, pos=wx.DefaultPosition, size=wx.DefaultSize, 
            style=wx.DEFAULT_DIALOG_STYLE
            ):

        wx.Dialog.__init__(self,parent,ID,title,pos,size,style)

        sizer = wx.BoxSizer(wx.VERTICAL)

        label = wx.StaticText(self, -1, "Verifying protocol description")
        sizer.Add(label, 0, wx.ALIGN_CENTRE|wx.ALL, 5)

        line = wx.StaticLine(self, -1, size=(20,-1), style=wx.LI_HORIZONTAL)
        sizer.Add(line, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.RIGHT|wx.TOP, 5)

        btnsizer = wx.StdDialogButtonSizer()
        
        btn = wx.Button(self, wx.ID_CANCEL)
        btnsizer.AddButton(btn)
        btnsizer.Realize()

        sizer.Add(btnsizer, 0, wx.ALIGN_CENTER_VERTICAL|wx.ALL, 5)

        self.SetSizer(sizer)
        sizer.Fit(self)

#---------------------------------------------------------------------------

class ResultWindow(wx.Frame):

    def __init__(
            self, mainwindow, ID, title, pos=wx.DefaultPosition, size=wx.DefaultSize, 
            style=wx.DEFAULT_DIALOG_STYLE
            ):

        self.mainwindow = mainwindow
        
        wx.Frame.__init__(self,mainwindow,ID,title,pos,size,style)

        self.thread = None
        self.Bind(wx.EVT_CLOSE, self.onCloseWindow)

        # Now continue with the normal construction of the dialog
        # contents
        sizer = wx.BoxSizer(wx.VERTICAL)

        # set up grid
        claims = mainwindow.claims
        self.grid = grid = wx.GridBagSizer(7,1+len(claims))

        def titlebar(x,title,width=1):
            txt = wx.StaticText(self,-1,title)
            font = wx.Font(14,wx.NORMAL,wx.NORMAL,wx.NORMAL)
            txt.SetFont(font)
            grid.Add(txt,(0,x),(1,width))

        titlebar(0,"Claim",5)
        if len(claims) > 0:
            sn = claims[0].stateName(2)
            resulttxt = sn[0].upper() + sn[1:]
        else:
            resultxt = "Results"
        titlebar(5,resulttxt,2)

        lastprot = None
        lastrole = None
        for index in range(0,len(claims)):
            cl = claims[len(claims)-index-1]
            # we reverse the display order of the claims!
            y = index+1

            # a support function
            def addtxt(txt,column):
                grid.Add(wx.StaticText(self,-1,txt),(y,column),(1,1),wx.ALIGN_CENTER_VERTICAL)

            # button for ok/fail
            tsize = (16,16)
            if cl.okay:
                bmp = wx.ArtProvider_GetBitmap(wx.ART_TICK_MARK,wx.ART_CMN_DIALOG,tsize)
            else:
                bmp = wx.ArtProvider_GetBitmap(wx.ART_CROSS_MARK,wx.ART_CMN_DIALOG,tsize)
            if not bmp.Ok():
                bmp = wx.EmptyBitmap(tsize)
            bmpfield = wx.StaticBitmap(self,-1,bmp)

            grid.Add(bmpfield,(y,0),(1,1),wx.ALIGN_CENTER_VERTICAL)

            # protocol, role, label
            prot = str(cl.protocol)
            if prot != lastprot:
                addtxt(prot,1)
                lastprot = prot
            role = str(cl.role)
            if role != lastrole:
                addtxt(role,2)
                lastrole = role
            addtxt(str(cl.shortlabel),3)

            claimdetails = str(cl.claimtype)
            if cl.parameter:
                claimdetails += " %s  " % (cl.parameter)
            addtxt(claimdetails,4)

            # add view button (if needed)
            n = len(cl.attacks)
            cl.button = wx.Button(self,-1,"%i %s" % (n,cl.stateName(n)))
            grid.Add(cl.button,(y,5),(1,1),wx.ALIGN_CENTER_VERTICAL)
            cl.button.Disable()
            if n > 0:
                # Aha, something to show
                self.Bind(wx.EVT_BUTTON, self.onViewButton,cl.button)

            # remark something about completeness
            remark = ""
            if not cl.complete:
                if n == 0:
                    # no attacks, no states within bounds
                    remark = "within bounds"
                else:
                    # some attacks/states within bounds
                    remark = "at least, maybe more"
            else:
                if n == 0:
                    # no attacks, no states
                    remark = "none"
                else:
                    # there exist n states/attacks (within any number of runs)
                    remark = "exactly"
            addtxt(" (%s)" % remark,6)
                
        sizer.Add(grid, 0,wx.ALIGN_CENTRE|wx.ALL,5)

        # # separator
        # line = wx.StaticLine(self, -1, size=(20,-1), style=wx.LI_HORIZONTAL)
        # sizer.Add(line, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.RIGHT|wx.TOP, 5)

        # btn = wx.Button(self, -1,"Close window")
        # self.Bind(wx.EVT_BUTTON,self.onCloseButton,btn)

        # sizer.Add(btn, 0, wx.ALIGN_CENTER_VERTICAL|wx.ALL|wx.ALIGN_RIGHT, 5)


        self.SetSizer(sizer)
        sizer.Fit(self)


    def onViewButton(self,evt):
        btn = evt.GetEventObject()
        (y,x) = self.grid.GetItemPosition(btn)
        n = len(self.mainwindow.claims)
        cln = n-y
        cl = self.mainwindow.claims[cln]
        w = Attackwindow.AttackWindow(cl)

    def onCloseWindow(self,evt):
        # TODO we should kill self.thread
        self.Destroy()

#---------------------------------------------------------------------------


def RunScyther(mainwin,mode):

    # Verification window

    verifywin = VerificationWindow(mainwin,-1,mode)
    verifywin.CenterOnScreen()
    verifywin.Show(True)

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

    # Cursor back to normal
    verifywin.SetCursor(wx.StockCursor(wx.CURSOR_ARROW))

    if mainwin.verified:
        # Great, we verified stuff, progress to the claim report
        title = "Scyther results : %s" % mode
        resultwin = ResultWindow(mainwin,-1,title)
        resultwin.Show(1)

        t = AttackThread(mainwin,resultwin)
        t.start()

        resultwin.thread = t
        resultwin.CenterOnScreen()
        resultwin.Show(True)





