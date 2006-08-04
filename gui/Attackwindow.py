#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import wx
import time

#---------------------------------------------------------------------------

""" Import scyther-gui components """
import Icon

#---------------------------------------------------------------------------

class AttackDisplay(wx.ScrolledWindow):
    def __init__(self, daddy, parent, attack):

        self.win = daddy
        self.attack = attack

        wx.ScrolledWindow.__init__(self,parent,id=-1)
        # Wait for the attack to be computed
        while not attack.file:
            time.sleep(1)

        self.Bind(wx.EVT_SIZE, self.OnSize)
        self.Image = wx.StaticBitmap(self, -1, wx.EmptyBitmap(1,1))
        self.box = wx.BoxSizer(wx.VERTICAL)
        self.box.Add(self.Image,1,wx.ALIGN_CENTER)
        self.hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.hbox.Add(self.box,1,wx.ALIGN_CENTER)
        self.SetSizer(self.hbox)

        filename = attack.file
        self.original = wx.Image(filename,wx.BITMAP_TYPE_PNG)


        self.update()

        # TODO self.Bind(wxSizeEvent

    def OnSize(self,event):
        self.update()
        event.Skip()

    def update(self):

        self.SetScrollbars(0,0,0,0,0,0)

        bmp = self.original
        if not bmp.Ok():
            bmp = wx.EmptyBitmap((1,1))
        else:
            if self.win.fit:
                W = bmp.GetWidth()
                H = bmp.GetHeight()
                (sw,sh) = self.win.GetClientSizeTuple()

                if W > sw:
                    # correct width
                    factor = float(sw) / W
                    W = sw
                    H = H * factor
                if H > sh:
                    # correct height
                    factor = float(sh) / H
                    H = sh
                    W = W * factor


                bmp = self.original.Scale(W,H)

        self.Image.SetBitmap(wx.BitmapFromImage(bmp))
        #self.box.SetItemMinSize(self.Image.GetContainingSizer())
        self.box.Layout()

        # wx.StaticBitmap(self, -1, bmp, (0, 0), (bmp.GetWidth(), bmp.GetHeight()))
        step = 20
        xn = int(bmp.GetWidth() / step) + 1
        yn = int(bmp.GetHeight() / step) + 1
        self.SetScrollbars(step,step,xn,yn,0,0)

        self.Refresh()


class AttackWindow(wx.Frame):
    def __init__(self,cl):
        super(AttackWindow, self).__init__(None, size=(400,800))
        self.claim = cl
        self.fit = False
        self.CreateInteriorWindowComponents()
        self.CreateExteriorWindowComponents()

        Icon.ScytherIcon(self)
        self.SetTitle()

    def SetTitle(self):

        tstr = self.claim.stateName(len(self.claim.attacks))
        tstr += " for claim %s" % self.claim.id
        super(AttackWindow, self).SetTitle(tstr)

    def CreateInteriorWindowComponents(self):
        ''' Create "interior" window components. In this case it is the
        attack picture. '''

        self.displays=[]
        attacks = self.claim.attacks
        n = len(attacks)
        if n <= 1:
            # Just a single window
            self.tabs = None
            self.displays.append(AttackDisplay(self,self,attacks[0]))
        else:
            # Multiple tabs
            self.tabs = wx.Notebook(self,-1)
            for i in range(0,n):
                disp = AttackDisplay(self,self.tabs,attacks[i])
                classname = "%s %i" % (self.claim.stateName(),(i+1))
                self.tabs.AddPage(disp, classname)
                self.displays.append(disp)

        self.Show(1)


    def CreateExteriorWindowComponents(self):
        ''' Create "exterior" window components, such as menu and status
        bars '''
        self.CreateStatusBar()
        self.SetupToolBar()

    def SetupToolBar(self):

        tb = self.CreateToolBar(wx.TB_HORIZONTAL
                | wx.NO_BORDER
                | wx.TB_FLAT
                | wx.TB_TEXT
                )

        # Add fit button
        bmp = wx.ArtProvider_GetBitmap(wx.ART_MISSING_IMAGE,wx.ART_TOOLBAR,(20,20))
        if not bmp.Ok():
            bmp = wx.EmptyBitmap(32,32)
        tb.AddCheckTool(wx.ID_ZOOM_FIT, bmp, bmp, 'Toggle zoom', 'Toggle zoom level')
        self.Bind(wx.EVT_TOOL, self.OnFit, id=wx.ID_ZOOM_FIT)

        tb.Realize()

        # And shortcut
        aTable = wx.AcceleratorTable([
                                      (wx.ACCEL_NORMAL, ord('Z'), wx.ID_ZOOM_FIT)
                                      ])
        self.SetAcceleratorTable(aTable)

    def update(self):
        for t in self.displays:
            t.update()

    def OnFit(self,event):

        if self.fit:
            self.fit = False
        else:
            self.fit = True
        self.update()

    def OnRealSize(self):

        self.fit = False
        self.update()

