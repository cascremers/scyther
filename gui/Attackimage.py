#!/usr/bin/python

#---------------------------------------------------------------------------

""" Import externals """
import os

#---------------------------------------------------------------------------

""" Import scyther-gui components """
import Tempfile

#---------------------------------------------------------------------------

class AttackImage:
    def __init__(self,dotdata):
        self.dotdata = dotdata
        self.png = ""

        self.MakeImage()    

    def MakeImage(self):
        """ Sets png """

        (fd,fpname) = Tempfile.tempcleaned(".dot")
        fp = os.fdopen(fd, "w")
        fp.write(self.dotdata)
        fp.close()

        (fd2,fpname2) = Tempfile.tempcleaned(".png")
        os.system("dot %s -Tpng >%s" % (fpname, fpname2))
        self.png = fpname2

        Tempfile.tempcleanearly((fd,fpname))

    def GetImage(self):

        return self.png

#---------------------------------------------------------------------------

