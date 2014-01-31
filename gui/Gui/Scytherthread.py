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
import threading

#---------------------------------------------------------------------------

""" Import scyther components """
import Scyther.Scyther
import Scyther.Error
from Scyther.Misc import *

""" Import scyther-gui components """
import Preference
import Attackwindow
import Icon
import Error
import Makeimage

#---------------------------------------------------------------------------
if Preference.havePIL:
    import Image
#---------------------------------------------------------------------------

class ScytherThread(threading.Thread):
    """
    Apply Scyther algorithm to input and retrieve results
    """

    # Override Thread's __init__ method to accept the parameters needed:
    def __init__ ( self, spdl, options="", callback=None, mode=None ):

        self.spdl = spdl
        self.options = options
        self.callback = callback
        self.mode = mode
        self.popenList = []
        threading.Thread.__init__ ( self )

    def storePopen(self,p):
        self.popenList.append(p)

    def cleanExit(self):
        # Cleanup of spawned processes
        for index,p in enumerate(self.popenList):
            try:
                p.kill()
            except:
                pass
        self.popenList = []

    def run(self):

        (scyther, claims, summary) = self.claimResults()

        # Results are done (claimstatus can be reported)
        if self.callback:
            wx.CallAfter(self.callback, scyther, claims, summary)

    def claimFixViewOne(self,claims):
        """
        This is a stupid hack as long as switches.useAttackBuffer in
        Scyther C code is false. It is currently false because Windows
        VISTA screwed up the standard C function tmpfile() (It's in a
        directory to which normal users cannot write...)
        """
        # TODO Notice the stupid default setting too ('2') which is
        # needed here. This really needs cleanup.
        if int(Preference.get('prune','2')) != 0:
            if claims:
                for cl in claims:
                    if len(cl.attacks) > 1:
                        # Fix it such that by default, only the best attack is
                        # shown, unless we are in characterize or check mode
                        # TODO [X] [CC] make switch-dependant.
                        if not self.mode in ["characterize","check"]:
                            cl.attacks = [cl.attacks[-1]]
                            """ Cutting invalidates exactness of attack/behaviour counts """
                            cl.complete = False

        return claims

    def claimResults(self):
        """ Convert spdl to result (using Scyther)
        """

        scyther = Scyther.Scyther.Scyther()

        scyther.options = self.options
        scyther.setInput(self.spdl)

        # verification start
        try:
            claims = scyther.verify(storePopen=self.storePopen)
        except Scyther.Error.ScytherError, el:
            claims = None
            pass

        summary = str(scyther)

        claims = self.claimFixViewOne(claims)

        return (scyther, claims, summary)

#---------------------------------------------------------------------------

class AttackThread(threading.Thread):

    """ This is a thread because it computes images from stuff in the
    background """

    # Override Thread's __init__ method to accept the parameters needed:
    def __init__ ( self, parent, resultwin, callbackclaim=None,callbackattack=None,callbackdone=None ):

        self.parent = parent
        self.resultwin = resultwin
        self.callbackclaim = callbackclaim
        self.callbackattack = callbackattack
        self.callbackdone = callbackdone
        self.totalattacks = 0
        for cl in self.parent.claims:
            for attack in cl.attacks:
                self.totalattacks += 1

        threading.Thread.__init__ ( self )

    def run(self):

        # create the images in the background
        # when the images of a claim are done, callback is called with
        # the claim
        self.makeImages()

    def makeImages(self):
        """ create images """

        done = 0
        for cl in self.parent.claims:
            for attack in cl.attacks:
                Makeimage.makeImage(attack,self)
                done += 1
                if self.callbackattack:
                    wx.CallAfter(self.callbackattack,attack,self.totalattacks,done)
            if self.callbackclaim:
                wx.CallAfter(self.callbackclaim,cl)
        if self.callbackdone:
            wx.CallAfter(self.callbackdone)


#---------------------------------------------------------------------------

class VerificationWindow(wx.Dialog):
    def __init__(
            self, parent, title, pos=wx.DefaultPosition, size=wx.DefaultSize, 
            style=wx.DEFAULT_DIALOG_STYLE
            ):

        wx.Dialog.__init__(self,parent,-1,title,pos,size,style)

        sizer = wx.BoxSizer(wx.VERTICAL)

        label = wx.StaticText(self, -1, "Verifying protocol description")
        sizer.Add(label, 0, wx.ALIGN_CENTRE|wx.ALL, 5)

        line = wx.StaticLine(self, -1, size=(20,-1), style=wx.LI_HORIZONTAL)
        sizer.Add(line, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.RIGHT|wx.TOP, 5)

        btnsizer = wx.StdDialogButtonSizer()
        
        btn = wx.Button(self, wx.ID_CANCEL)
        btnsizer.AddButton(btn)
        btnsizer.Realize()

        sizer.Add(btnsizer, 0, wx.ALIGN_CENTER_VERTICAL|wx.ALL|wx.ALIGN_CENTER, 5)

        self.SetSizer(sizer)
        sizer.Fit(self)

        self.Center()
        self.Show(True)

#---------------------------------------------------------------------------

class ErrorWindow(wx.Dialog):
    def __init__(
            self, parent, title, pos=wx.DefaultPosition, size=wx.DefaultSize, 
            style=wx.DEFAULT_DIALOG_STYLE,errors=[]
            ):

        wx.Dialog.__init__(self,parent,-1,title,pos,size,style)

        sizer = wx.BoxSizer(wx.VERTICAL)

        label = wx.StaticText(self, -1, "Errors")
        sizer.Add(label, 0, wx.ALIGN_LEFT|wx.ALL, 5)

        line = wx.StaticLine(self, -1, size=(20,-1), style=wx.LI_HORIZONTAL)
        sizer.Add(line, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.RIGHT|wx.TOP, 5)

        etxt = ""
        prefix = "error: "
        for er in errors:
            if er.startswith(prefix):
                er = er[len(prefix):]
            etxt = etxt + "%s\n" % (er)

        label = wx.StaticText(self, -1, etxt)
        sizer.Add(label, 0, wx.ALIGN_LEFT|wx.ALL, 5)

        line = wx.StaticLine(self, -1, size=(20,-1), style=wx.LI_HORIZONTAL)
        sizer.Add(line, 0, wx.GROW|wx.ALIGN_CENTER_VERTICAL|wx.RIGHT|wx.TOP, 5)

        btnsizer = wx.StdDialogButtonSizer()
        
        btn = wx.Button(self, wx.ID_OK)
        btnsizer.AddButton(btn)
        btnsizer.Realize()

        sizer.Add(btnsizer, 0, wx.ALIGN_CENTER_VERTICAL|wx.ALL|wx.ALIGN_CENTER, 5)

        self.SetSizer(sizer)
        sizer.Fit(self)

#---------------------------------------------------------------------------

class ResultWindow(wx.Frame):

    """
    Displays the claims status and contains buttons to show the actual
    attack graphs
    """

    def __init__(
            self, parent, parentwindow, title, pos=wx.DefaultPosition, size=wx.DefaultSize, 
            style=wx.DEFAULT_DIALOG_STYLE
            ):

        wx.Frame.__init__(self,parentwindow,-1,title,pos,size,style)

        Icon.ScytherIcon(self)

        self.parent = parent
        self.thread = None
        self.Bind(wx.EVT_CLOSE, self.onCloseWindow)

        self.CreateStatusBar()
        self.BuildTable()

    def onViewButton(self,evt):
        btn = evt.GetEventObject()
        try:
            w = Attackwindow.AttackWindow(btn.claim)
            w.Show(True)
        except Error.PILError:
            Error.ShowAndReturn("Problem with PIL imaging library: disabled zooming. Please retry to verify the protocol again.")
            self.onCloseWindow(None)

    def onCloseWindow(self,evt):
        """ TODO we should kill self.thread """

        # Clean up
        self.parent.claims = None

        self.Destroy()

    def BuildTable(self):
        # Now continue with the normal construction of the dialog
        # contents

        # For these claims...
        claims = self.parent.claims

        # set up grid
        self.grid = grid = wx.GridBagSizer(0,0)
        #self.grid = grid = wx.GridBagSizer(7,1+len(claims))

        def titlebar(x,title,width=1):
            txt = wx.StaticText(self,-1,title)
            font = wx.Font(14,wx.FONTFAMILY_DEFAULT,wx.FONTSTYLE_NORMAL,wx.FONTWEIGHT_BOLD)
            txt.SetFont(font)
            grid.Add(txt,(0,x),(1,width),wx.ALL,10)

        titlebar(0,"Claim",4)
        titlebar(4,"Status",2)
        titlebar(6,"Comments",1)

        self.lastprot = None
        self.lastrole = None
        views = 0
        for index in range(0,len(claims)):
            views += self.BuildClaim(grid,claims[index],index+1)

        if views > 0:
            titlebar(7,"Patterns",1)

        self.SetSizer(grid)
        self.Fit()

    def BuildClaim(self,grid,cl,ypos):
        # a support function
        def addtxt(txt,column):
            txt = txt.replace("-","_")  # Strange fix for wx.StaticText as it cuts off the display.
            grid.Add(wx.StaticText(self,-1,txt),(ypos,column),(1,1),wx.ALIGN_CENTER_VERTICAL|wx.ALL,10)

        n = len(cl.attacks)
        xpos = 0

        # protocol, role, label
        prot = str(cl.protocol)
        showP = False
        showR = False
        if prot != self.lastprot:
            self.lastprot = prot
            showP = True
            showR = True
        role = str(cl.role)
        if role != self.lastrole:
            self.lastrole = role
            showR = True
        if showP:
            addtxt(prot,xpos)
        if showR:
            addtxt(role,xpos+1)
        xpos += 2
        
        # claim id
        addtxt(str(cl.id),xpos)
        xpos += 1

        # claim parameters
        claimdetails = str(cl.claimtype)
        if cl.parameter:
            claimdetails += " %s" % (cl.parameter)
        # Cut off if very very long
        if len(claimdetails) > 50:
            claimdetails = claimdetails[:50] + "..."
        addtxt(claimdetails + "  ",xpos)
        xpos += 1

        # button for ok/fail
        if None:
            # old style buttons (but they looked ugly on windows)
            tsize = (16,16)
            if cl.okay:
                bmp = wx.ArtProvider_GetBitmap(wx.ART_TICK_MARK,wx.ART_CMN_DIALOG,tsize)
            else:
                bmp = wx.ArtProvider_GetBitmap(wx.ART_CROSS_MARK,wx.ART_CMN_DIALOG,tsize)
            if not bmp.Ok():
                bmp = wx.EmptyBitmap(tsize)
            bmpfield = wx.StaticBitmap(self,-1,bmp)
            grid.Add(bmpfield,(ypos,xpos),(1,1),wx.ALIGN_CENTER_VERTICAL|wx.ALL,10)
        else:
            # new style text control Ok/Fail
            rankc = cl.getColour()
            rankt = cl.getOkay()
            txt = wx.StaticText(self,-1,rankt)
            font = wx.Font(11,wx.FONTFAMILY_DEFAULT,wx.FONTSTYLE_NORMAL,wx.FONTWEIGHT_BOLD)
            txt.SetFont(font)
            txt.SetForegroundColour(rankc)
            grid.Add(txt,(ypos,xpos),(1,1),wx.ALL,10)
        xpos += 1

        # verified?
        vt = cl.getVerified()
        if vt:
            addtxt(vt,xpos)
        xpos += 1

        # remark something 
        addtxt(cl.getComment(),xpos)
        xpos += 1
                
        # add view button (enabled later if needed)
        if n > 0:
            cl.button = wx.Button(self,-1,"%i %s" % (n,cl.stateName(n)))
            cl.button.claim = cl
            grid.Add(cl.button,(ypos,xpos),(1,1),wx.ALIGN_CENTER_VERTICAL|wx.ALL,5)
            cl.button.Disable()
            if n > 0:
                # Aha, something to show
                self.Bind(wx.EVT_BUTTON, self.onViewButton,cl.button)
        else:
            cl.button = None
        xpos += 1

        # Return 1 if there is a view possible
        if n > 0:
            return 1
        else:
            return 0


#---------------------------------------------------------------------------

class ScytherRun(object):

    def __init__(self,mainwin,mode,spdl,errorcallback=None):

        self.mainwin = mainwin
        self.mode = mode
        self.spdl = spdl
        self.verified = False
        self.options = mainwin.settings.ScytherArguments(mode)
        self.errorcallback=errorcallback
        self.SThread = None

        self.main()

    def closer(self,ev):
        # Triggered when the window is closed/verification cancelled
        t = self.SThread
        if t != None:
            self.SThread = None
            t.cleanExit()
        try:
            self.verifywin.Destroy()
        except:
            pass
        self.verifywin = None
        ev.Skip()

    def main(self):
        """
        Start process
        """

        title = "Running Scyther %s process" % self.mode
        # start the window and show until something happens
        # if it terminates, this is a cancel, and should also kill the thread. (what happens to a spawned Scyther in that case?)
        # if the thread terminames, it should close the window normally, and we end up here as well.
        #val = self.verifywin.ShowModal()
        self.verifywin = VerificationWindow(self.mainwin,title)

        # Check sanity of Scyther thing here (as opposed to the thread)
        # which makes error reporting somewhat easier
        try:
            Scyther.Scyther.Check()
        except Scyther.Error.BinaryError, e:
            # e.file is the supposed location of the binary
            text = "Could not find Scyther binary at\n%s" % (e.file)
            Error.ShowAndExit(text)
        
        # start the thread
        self.verifywin.SetCursor(wx.StockCursor(wx.CURSOR_WAIT))
        self.verifywin.Bind(wx.EVT_CLOSE, self.closer)
        self.verifywin.Bind(wx.EVT_WINDOW_DESTROY, self.closer)
        self.verifywin.Bind(wx.EVT_BUTTON, self.closer, id=wx.ID_CANCEL)

        self.SThread = ScytherThread(self.spdl, self.options, self.verificationDone, self.mode)
        self.SThread.start()

        # after verification, we proceed to the callback below...

    def verificationDone(self, scyther, claims, summary):
        """
        This is where we end up after a callback from the thread, stating that verification succeeded.
        """

        if self.verifywin == None:
            return

        self.scyther = scyther
        self.claims = claims
        self.summary = summary

        self.verified = True
        self.verifywin.Close()

        # Process the claims
        if self.scyther.errorcount == 0:
            self.verificationOkay()
        else:
            self.verificationErrors()

    def verificationOkay(self):

        # Great, we verified stuff, progress to the claim report
        title = "Scyther results : %s" % self.mode
        self.resultwin = resultwin = ResultWindow(self,self.mainwin,title)

        def attackDone(attack,total,done):
            if resultwin:
                txt = "Generating attack graphs (%i of %i done)." % (done,total)
                resultwin.SetStatusText(txt)
                #resultwin.Refresh()

        def claimDone(claim):
            if resultwin:
                if claim.button and len(claim.attacks) > 0:
                    claim.button.Enable()

        def allDone():
            if resultwin:
                resultwin.SetCursor(wx.StockCursor(wx.CURSOR_ARROW))
                resultwin.SetStatusText("Done.")

        resultwin.Center()
        resultwin.Show(True)
        resultwin.SetCursor(wx.StockCursor(wx.CURSOR_ARROWWAIT))

        wx.Yield()

        t = AttackThread(self,resultwin,claimDone,attackDone,allDone)
        t.start()

        resultwin.thread = t

    def verificationErrors(self):
        """
        Verification process generated errors. Show them.
        """

        if self.errorcallback:
            self.errorcallback(self.scyther.errors)
        title = "Scyther errors : %s" % self.mode
        errorwin = ErrorWindow(self.mainwin,title,errors=self.scyther.errors)
        errorwin.Center()
        val = errorwin.ShowModal()

#---------------------------------------------------------------------------
# vim: set ts=4 sw=4 et list lcs=tab\:>-:
