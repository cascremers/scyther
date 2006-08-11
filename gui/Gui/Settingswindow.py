#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx

#---------------------------------------------------------------------------

""" Import scyther-gui components """
import Preference
import Scyther.Claim as Claim

#---------------------------------------------------------------------------

class SettingsWindow(wx.Panel):

    def __init__(self,parent,daddy):
        wx.Panel.__init__(self,parent,-1)

        self.win = daddy
        space = 10
        grid = wx.GridBagSizer(hgap=space,vgap=space)
        ypos = 0

        # Bound on the number of runs
        self.maxruns = int(Preference.get('maxruns','5'))
        txt = wx.StaticText(self,-1,"Maximum number of runs (0 disables bound)")
        ctrl = wx.SpinCtrl(self, -1, "",style=wx.RIGHT)
        ctrl.SetRange(0,100)
        ctrl.SetValue(self.maxruns)
        self.Bind(wx.EVT_SPINCTRL,self.EvtRuns,ctrl)
        grid.Add(ctrl,(ypos,0))
        grid.Add(txt,(ypos,1))
        ypos += 1

        # Matchin options
        self.match = int(Preference.get('match','0'))
        claimoptions = ['typed matching','find basic type flaws','find all type flaws']
        r2 = wx.StaticText(self,-1,"Matching type")
        l2 = self.ch = wx.Choice(self,-1,choices=claimoptions)
        l2.SetSelection(self.match)
        self.Bind(wx.EVT_CHOICE,self.EvtMatch,l2)
        grid.Add(l2,(ypos,0))
        grid.Add(r2,(ypos,1))
        ypos += 1

        ### MISC expert stuff

        # Bound on the number of classes/attacks
        self.maxattacks = int(Preference.get('maxattacks','100'))
        stname = Claim.stateDescription(True,2,False)
        atname = Claim.stateDescription(False,2,False)
        txt = "%s/%s" % (stname,atname)
        r9 = wx.StaticText(self,-1,"Maximum number of %s for all claims combined (0 disables maximum)" % txt)
        l9 = wx.SpinCtrl(self, -1, "",style=wx.RIGHT)
        l9.SetRange(0,100)
        l9.SetValue(self.maxattacks)
        self.Bind(wx.EVT_SPINCTRL,self.EvtMaxAttacks,l9)
        grid.Add(l9,(ypos,0))
        grid.Add(r9,(ypos,1))
        ypos += 1

        self.misc = Preference.get('scytheroptions','')
        r10 = wx.StaticText(self,-1,"Additional parameters for the Scyther tool")
        l10 = wx.TextCtrl(self,-1,self.misc,size=(150,-1))
        self.Bind(wx.EVT_TEXT,self.EvtMisc,l10)
        grid.Add(l10,(ypos,0))
        grid.Add(r10,(ypos,1))
        ypos += 1

        # Combine
        self.SetSizer(grid)
        self.SetAutoLayout(True)

    def EvtMatch(self,evt):
        self.match = evt.GetInt()

    def EvtRuns(self,evt):
        self.maxruns = evt.GetInt()

    def EvtMaxAttacks(self,evt):
        self.maxattacks = evt.GetInt()

    def EvtMisc(self,evt):
        self.misc = evt.GetString()

    def ScytherArguments(self,mode):
        """ Note: constructed strings should have a space at the end to
            correctly separate the options.
        """

        tstr = ""

        # Number of runs
        tstr += "--max-runs=%s " % (str(self.maxruns))
        # Matching type
        tstr += "--match=%s " % (str(self.match))
        # Max attacks/classes
        if self.maxattacks != 0:
            tstr += "--max-attacks=%s " % (str(self.maxattacks))

        # Verification type
        if mode == "check":
            tstr += "--check "
        elif mode == "autoverify":
            tstr += "--auto-claims "
        elif mode == "statespace":
            tstr += "--state-space "

        # Anything else?
        if self.misc != "":
            tstr += " " + self.misc + " "

        return tstr

#---------------------------------------------------------------------------
