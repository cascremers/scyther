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
import wx
import sys

#---------------------------------------------------------------------------

""" Import scyther-gui components """
import Preference
import Scyther.Claim as Claim

#---------------------------------------------------------------------------

class MyGrid(wx.GridBagSizer):

    def __init__(self,parent):
        wx.GridBagSizer.__init__(self,hgap=5, vgap=5)
        self.ypos = 0
        self.parent = parent

    def stepAdd(self,ctrl,txt):
        self.Add(txt,(self.ypos,0),flag=wx.ALIGN_LEFT|wx.ALIGN_CENTER_VERTICAL)
        self.Add(ctrl,(self.ypos,1),flag=wx.ALIGN_LEFT)
        self.ypos += 1

    def lineAdd(self):
        return
        line = wx.StaticLine(self.parent,-1)
        # Currently it is not expanded, and thus invisible.
        self.Add(line,pos=(self.ypos,0),span=(1,2),flag=wx.TOP|wx.BOTTOM)
        self.ypos += 1

    def titleAdd(self,title,firstLine=True):
        if firstLine:
            self.lineAdd()
        self.ypos += 1
        txt = wx.StaticText(self.parent,-1,title)
        font = wx.Font(12,wx.DEFAULT,wx.NORMAL,wx.BOLD)
        txt.SetFont(font)
        self.Add(txt,pos=(self.ypos,0),span=(1,2),flag=wx.ALIGN_LEFT)
        self.ypos += 1
        self.lineAdd()

#---------------------------------------------------------------------------

class SettingsWindow(wx.Panel):

    def __init__(self,parent,daddy):
        wx.Panel.__init__(self,parent,-1)
        self.win = daddy

        # layout the stuff
        grid = MyGrid(self)

        ### Parameters
        grid.titleAdd("Verification parameters",False)

        # Bound on the number of runs
        self.maxruns = int(Preference.get('maxruns','5'))
        txt = wx.StaticText(self,-1,"Maximum number of runs\n(0 disables bound)")
        ctrl = wx.SpinCtrl(self, -1, "",style=wx.RIGHT)
        ctrl.SetRange(0,100)
        ctrl.SetValue(self.maxruns)
        self.Bind(wx.EVT_SPINCTRL,self.EvtRuns,ctrl)
        grid.stepAdd(ctrl,txt)

        # Matchin options
        self.match = int(Preference.get('match','0'))
        claimoptions = ['typed matching','find basic type flaws','find all type flaws']
        r2 = wx.StaticText(self,-1,"Matching type")
        l2 = self.ch = wx.Choice(self,-1,choices=claimoptions)
        l2.SetSelection(self.match)
        self.Bind(wx.EVT_CHOICE,self.EvtMatch,l2)
        grid.stepAdd(l2,r2)

        ### Security model
        grid.titleAdd("Adversary compromise model")

        ## Partner definition 
        #self.partnerdefinition = int(Preference.get('partnerdefinition','1'))
        #claimoptions = ['Temporal (Experimental)','Matching conversations','Session identifier (SID)']
        #r4 = wx.StaticText(self,-1,"Partner definition")
        #l4 = self.ch = wx.Choice(self,-1,choices=claimoptions)
        #l4.SetSelection(self.partnerdefinition)
        #self.Bind(wx.EVT_CHOICE,self.EvtPartnerdefinition,l4)
        #grid.stepAdd(l4,r4)

        # Propagate choice for SSR
        def SSRpropagate():
            val = Preference.get("--SSR=")
            if (val == True) or (int(val) == 1):
                InferToggle.Enable()
            else:
                InferToggle.Enable(False)

        # Toggle stuff
        def mytoggle(btn,pref,event):
            res = btn.GetValue()
            if res == True:
                val = 1
            else:
                val = 0
            Preference.set(pref,val)
            SSRpropagate()

        # Checkboxes
        def toggler(description,buttontxt,pref):
            oldstate = Preference.get(pref,0)
            desc = wx.StaticText(self,-1,description)
            btn = wx.CheckBox(self,-1,buttontxt)
            btn.SetValue(int(oldstate) == 1)
            tf = lambda event: mytoggle(btn,pref,event)
            self.Bind(wx.EVT_CHECKBOX, tf, btn)
            grid.stepAdd(btn,desc)
            return btn

        toggler("Long-term Key Reveal","Others (DY)","--LKRothers=")
        
        # myradio
        def myradio(rdb,pref,event):
            Preference.set(pref,int(rdb.GetSelection()))

        toggler("Long-term Key Reveal","Actor (KCI)","--LKRactor=")

        # LKRaftercorrect variants
        desc = wx.StaticText(self,-1,"   Long-term Key Reveal after claim")
        options = ['None (DY)','aftercorrect (wPFS)','after (PFS)']
        rdb = wx.RadioBox(self,-1,"",(10,10),wx.DefaultSize,options,1)
        rdb.SetSelection(int(Preference.get("LKRafter")))
        self.Bind(wx.EVT_RADIOBOX, lambda event: myradio(rdb, "LKRafter", event), rdb)
        grid.stepAdd(rdb,desc)
        
        toggler("Session-Key Reveal","","--SKR=")
        toggler("Random Reveal","","--RNR=")
        toggler("State Reveal","","--SSR=")
        InferToggle = toggler("   Automatically infer local state","","--SSRinfer=")
        SSRpropagate()

        ### MISC expert stuff
        grid.titleAdd("Advanced parameters")

        # Continue after finding the first attack
        self.prune = int(Preference.get('prune','2'))
        claimoptions = ['Find all attacks','Find first attack','Find best attack']
        r8 = wx.StaticText(self,-1,"Search pruning")
        l8 = self.ch = wx.Choice(self,-1,choices=claimoptions)
        l8.SetSelection(self.prune)
        self.Bind(wx.EVT_CHOICE,self.EvtPrune,l8)
        grid.stepAdd(l8,r8)

        # Bound on the number of patterns
        self.maxattacks = int(Preference.get('maxattacks','10'))
        r9 = wx.StaticText(self,-1,"Maximum number of patterns\nper claim")
        l9 = wx.SpinCtrl(self, -1, "",style=wx.RIGHT)
        l9.SetRange(0,100)
        l9.SetValue(self.maxattacks)
        self.Bind(wx.EVT_SPINCTRL,self.EvtMaxAttacks,l9)
        grid.stepAdd(l9,r9)

        self.misc = Preference.get('scytheroptions','')
        r10 = wx.StaticText(self,-1,"Additional backend parameters")
        l10 = wx.TextCtrl(self,-1,self.misc,size=(200,-1))
        self.Bind(wx.EVT_TEXT,self.EvtMisc,l10)
        grid.stepAdd(l10,r10)

        ### Graph output stuff
        grid.titleAdd("Graph output parameters")

        # Bound on the number of classes/attacks
        if sys.platform.startswith("lin"):
            defsize = 14
        else:
            defsize = 11
        self.fontsize = int(Preference.get('fontsize',defsize))
        txt = wx.StaticText(self,-1,"Attack graph font size\n(in points)")
        ctrl = wx.SpinCtrl(self, -1, "",style=wx.RIGHT)
        ctrl.SetRange(6,32)
        ctrl.SetValue(self.fontsize)
        self.Bind(wx.EVT_SPINCTRL,self.EvtFontsize,ctrl)
        grid.stepAdd(ctrl,txt)

        ### Combine
        grid.lineAdd()
        self.SetSizer(grid)
        self.SetAutoLayout(True)

    def EvtMatch(self,evt):
        self.match = evt.GetInt()

    def EvtPartnerdefinition(self,evt):
        self.partnerdefinition = evt.GetInt()

    def EvtLocalcompromise(self,evt):
        #self.localcompromise = evt.GetInt()
        pass

    def EvtRuns(self,evt):
        self.maxruns = evt.GetInt()

    def EvtFontsize(self,evt):
        self.fontsize = evt.GetInt()

    def EvtPrune(self,evt):
        self.prune = evt.GetInt()
        Preference.set('prune',self.prune)

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

        # Compromise type
        #tstr += "--local-compromise=%s " % (str(self.localcompromise))
        # Partner definition
        #tstr += "--partner-definition=%s " % (str(self.partnerdefinition))

        # Prune (has to go BEFORE max attacks)
        tstr += "--prune=%s" % (str(self.prune))
        # Max attacks/classes
        if self.maxattacks != 0:
            tstr += "--max-attacks=%s " % (str(self.maxattacks))

        # Take standard arguments
        for pk in Preference.getkeys():
            if pk.startswith("--"):
                # Switch type preference
                if pk.endswith("="):
                    # Argument
                    tstr += "%s%s " % (pk,Preference.get(pk))
                else:
                    # Just enabling if 1 or True
                    val = Preference.get(pk)
                    if val == True or (int(val) == 1):
                        tstr += "%s " % pk

        # Parse LKR after type
        lkratype = int(Preference.get("LKRafter"))
        lkratxt = ["","--LKRaftercorrect=1 ","--LKRafter=1 "]
        tstr += lkratxt[lkratype]

        # Verification type
        if mode == "check":
            tstr += "--check "
        elif mode == "autoverify":
            tstr += "--auto-claims "
        elif mode == "characterize":
            tstr += "--state-space "

        # Anything else?
        if self.misc != "":
            tstr += " " + self.misc + " "

        return str(tstr)    # turn it into a str (might have been unicode weirdness)

#---------------------------------------------------------------------------
