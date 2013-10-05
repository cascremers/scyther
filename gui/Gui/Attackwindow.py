#!/usr/bin/python
from __future__ import division # 2.2+-only
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
import os
from Misc import *

#---------------------------------------------------------------------------

""" Import scyther-gui components """
import Icon
import Preference
import Error

#---------------------------------------------------------------------------
try:
    import Image
except ImportError:
    pass

#---------------------------------------------------------------------------

class AttackDisplay(wx.ScrolledWindow):
    """
    Display an attack (inside a tab or not)
    """
    def __init__(self, daddy, parent, attack):

        self.win = daddy
        self.attack = attack

        wx.ScrolledWindow.__init__(self,parent,id=-1)

        self.Bind(wx.EVT_SIZE, self.OnSize)
        self.Image = wx.StaticBitmap(self, -1, wx.EmptyBitmap(1,1))
        self.box = wx.BoxSizer(wx.VERTICAL)
        self.box.Add(self.Image,1,wx.ALIGN_CENTER)
        self.hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.hbox.Add(self.box,1,wx.ALIGN_CENTER)
        self.SetSizer(self.hbox)

        self.original = None

        filename = attack.file
        if attack.filetype == "png":
            self.original = wx.Image(filename,wx.BITMAP_TYPE_PNG)
        elif attack.filetype == "ps":
            # depends on PIL lib
            try:
                self.original = Image.open(filename)
            except:
                Preference.doNotUsePIL()
                raise Error.PILError
        else:
            print "Unknown file type %s." % (self.filetype)

        # TODO self.Bind(wxSizeEvent
        self.update(True)
        self.Fit()

    def OnSize(self,event):
        self.update(False)
        event.Skip()

    def update(self,force=True):

        if not force:
            if not self.win.fit:
                return

        # This is needed, don't ask me why.
        self.SetScrollbars(0,0,0,0,0,0)

        (framewidth,frameheight) = self.GetClientSizeTuple()
        (virtualwidth,virtualheight) = (framewidth,frameheight)

        def makefit(width,height):
            if self.win.fit:
                # determine scaling factors for fitting
                wfactor = float(framewidth) / width
                hfactor = float(frameheight) / height

                # select smallest factor (so it will fit)
                if hfactor < wfactor:
                    factor = hfactor
                else:
                    factor = wfactor
    
                # apply scaling factor
                width = width * factor
                height = height * factor
            else:
                factor = 1.0

            return (factor, int(width), int(height))

        if self.attack.filetype == "png":
            bmp = self.original
            if not bmp.Ok():
                bmp = wx.EmptyImage(1,1)
            else:
                (originalwidth,originalheight) = (bmp.GetWidth(), bmp.GetHeight())
                if self.win.fit:
                    (factor, virtualwidth, virtualheight) = makefit(originalwidth,originalheight)
                    bmp = self.original.Scale(virtualwidth,virtualheight)
            self.Image.SetBitmap(wx.BitmapFromImage(bmp))

        elif self.attack.filetype == "ps":
            pil = self.original.copy()
            (originalwidth,originalheight) = pil.size
            (factor, virtualwidth, virtualheight) = makefit(originalwidth,originalheight)
            # we really only want antialias when it's smaller
            if factor < 1.0:
                pil.thumbnail((virtualwidth,virtualheight),Image.ANTIALIAS)
            else:
                pil.thumbnail((virtualwidth,virtualheight))

            image = wx.EmptyImage(pil.size[0],pil.size[1])
            image.SetData(pil.convert('RGB').tostring())
            self.Image.SetBitmap(image.ConvertToBitmap())

        else:
            print "Unknown file type %s." % (self.attack.filetype)

        self.SetVirtualSize((virtualwidth,virtualheight))

        #self.box.SetItemMinSize(self.Image.GetContainingSizer())
        self.box.Layout()

        step = 20
        xn = int(virtualwidth // step) + 1
        yn = int(virtualheight // step) + 1
        self.SetScrollbars(step,step,xn,yn,0,0)

        """
        Pop up menu
        """
        self.popupmenu = wx.Menu()
        item = self.popupmenu.Append(-1,"Export image (.png)")
        self.Bind(wx.EVT_MENU, self.OnExportPng, item)
        item = self.popupmenu.Append(-1,"Export image (.ps)")
        self.Bind(wx.EVT_MENU, self.OnExportPs, item)
        item = self.popupmenu.Append(-1,"Export image (.pdf)")
        self.Bind(wx.EVT_MENU, self.OnExportPdf, item)
        item = self.popupmenu.Append(-1,"Export image (.svg)")
        self.Bind(wx.EVT_MENU, self.OnExportSvg, item)
        item = self.popupmenu.Append(-1,"Export image (.fig)")
        self.Bind(wx.EVT_MENU, self.OnExportFig, item)
        item = self.popupmenu.Append(-1,"Export graphviz data (.dot)")
        self.Bind(wx.EVT_MENU, self.OnExportDot, item)

        self.Bind(wx.EVT_CONTEXT_MENU, self.OnShowPopup)

        self.Refresh()

    def OnShowPopup(self, event):
        pos = event.GetPosition()
        pos = self.Image.ScreenToClient(pos)
        self.PopupMenu(self.popupmenu, pos)

    def OnPopupItemSelected(self, event):
        item = self.popupmenu.FindItemById(event.GetId())
        text = item.GetText()
        wx.MessageBox("You selected item %s" % text)

    def askUserForFilename(self, **dialogOptions):
        dialog = wx.FileDialog(self, **dialogOptions)
        if dialog.ShowModal() == wx.ID_OK:
            res = "%s/%s" % (dialog.GetDirectory(), dialog.GetFilename())
        else:
            res = None
        dialog.Destroy()
        return res

    def saveFileName(self, ext):
        (p,r,l) = self.win.claim.triplet()
        prefix = "pattern-%s_%s_%s-%s" % (p,r,l,self.attack.id)
        suggested = "%s.%s" % (prefix,ext)
        res = self.askUserForFilename(style=wx.SAVE, wildcard="*.%s" % (ext), defaultFile = "%s" % (suggested))
        return res

    def exportImage(self, type,ext=None):
        if ext == None:
            ext = type
        res = self.saveFileName(ext)
        if res != None:
            cmd = "dot -T%s" % (type)
            cmdpushwrite(cmd,self.attack.scytherDot,res)

    def OnExportPng(self, event):
        self.exportImage("png")

    def OnExportPs(self, event):
        self.exportImage("ps")

    def OnExportPdf(self, event):
        self.exportImage("pdf")

    def OnExportSvg(self, event):
        self.exportImage("svg")

    def OnExportFig(self, event):
        self.exportImage("fig")

    def OnExportDot(self, event):
        res = self.saveFileName("dot")
        if res != None:
            fp = open(res,'w')
            fp.write(self.attack.scytherDot)
            fp.close()





#---------------------------------------------------------------------------

class AttackWindow(wx.Frame):
    def __init__(self,cl):
        super(AttackWindow, self).__init__(None, size=(800,800))

        self.claim = cl

        # TODO maybe fitting defaults should come from Preferences.
        # Now, it is default no even if we have PIL, for performance
        # reasons.
        self.fit = False

        self.CreateInteriorWindowComponents()

        Icon.ScytherIcon(self)
        self.SetTitle()

    def SetTitle(self):

        tstr = self.claim.stateName(len(self.claim.attacks),True)
        tstr += " for claim %s" % self.claim.id
        super(AttackWindow, self).SetTitle(tstr)

    def CreateInteriorWindowComponents(self):
        ''' Create "interior" window components. In this case it is the
        attack picture. '''

        sizer = wx.BoxSizer(wx.VERTICAL)

        # Make zoom buttons
        if Preference.usePIL():
            buttons = wx.BoxSizer(wx.HORIZONTAL)
            bt = wx.ToggleButton(self,-1,"Fit to window")
            bt.SetValue(self.fit)
            buttons.Add(bt,0)
            self.Bind(wx.EVT_TOGGLEBUTTON, self.OnFit, bt)
            sizer.Add(buttons, 0, wx.ALIGN_LEFT)
        
        # Add attacks (possible with tabs)
        self.displays=[]
        attacks = self.claim.attacks

        n = len(attacks)
        if n <= 1:
            # Just a single window
            dp = AttackDisplay(self, self, attacks[0])
            self.displays.append(dp)
        else:
            # Multiple tabs
            dp = wx.Notebook(self,-1)
            for i in range(0,n):
                disp = AttackDisplay(self,dp,attacks[i])
                classname = "%s %i" % (self.claim.stateName(1,True),(i+1))
                dp.AddPage(disp, classname)
                self.displays.append(disp)

        sizer.Add(dp, 1, wx.EXPAND,1)

        self.SetSizer(sizer)

    def update(self,force=False):
        for t in self.displays:
            t.update(force)

    def OnFit(self,event):

        if self.fit:
            self.fit = False
        else:
            self.fit = True
        self.update(True)

    def OnRealSize(self):

        self.fit = False
        self.update(True)

    def OnSize(self):
        self.Refresh()

    def OnZoom100(self,evt):
        self.fit = False
        self.update(True)
        self.Refresh()

    def OnZoomFit(self,evt):
        self.fit = True
        self.update(True)
        self.Refresh()

#---------------------------------------------------------------------------
# vim: set ts=4 sw=4 et list lcs=tab\:>-:
