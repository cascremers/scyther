#!/usr/bin/python
#
# Scyther interface
#

#---------------------------------------------------------------------------

""" Import externals """
import os
import sys
import StringIO
import tempfile

#---------------------------------------------------------------------------

""" Import scyther components """
import XMLReader
from Misc import *

#---------------------------------------------------------------------------

class Scyther(object):
    def __init__ ( self):
        self.program = "scyther"
        self.options = ""
        self.spdl = None
        self.claims = None

    def setInput(self,spdl):
        self.spdl = spdl

    def setFile(self,filename):
        self.spdl = ""
        fp = open(filename,"r")
        for l in fp.readlines():
            self.spdl += l
        fp.close()

    def verify(self):

        if self.spdl:
            # Write spdl to temp file
            fp = tempfile.NamedTemporaryFile()
            fp.write(self.spdl)
            fp.flush()

            # Run Scyther on temp file
            self.cmd = "%s %s --dot-output --xml-output --plain '%s'" % (self.program,self.options,fp.name)

            # If we are on windows, we don't get stderr. Maybe we need a
            # switch to enforce this.
            if sys.platform.startswith('linux'):
                cmdline = "%s 2>/dev/null" % (self.cmd)
            else:
                # Non-linux does not generate stderr anyway
                cmdline = "%s" % (self.cmd)

            result = os.popen(cmdline)

            xmlinput = result.read()


            fp.close()

            xmlfile = StringIO.StringIO(xmlinput)
            reader = XMLReader.XMLReader()
            self.claims = reader.readXML(xmlfile)


            # Cleanup
            del(xmlinput)
            del(xmlfile)
            return self.claims

        else:
            # No input yet!
            return ""

    def __str__(self):
        if self.claims:
            s = ""
            for cl in self.claims:
                s += str(cl) + "\n"
            return s
        else:
            return "Scyther has not been run yet."


def basictest():
    # Some basic testing
    if sys.platform.startswith('win'):
        print "Dir test"
        p = os.popen("dir")
        print p.read()
        print p.close()
        confirm("See the dir?")
   
    # Scyther
    x = Scyther()

    if sys.platform.startswith('win'):
        x.program = "c:\\Scyther.exe"
        if not os.path.isfile(x.program):
            print "I can't find the Scyther executable %s" % (x.program)

    x.setFile("ns3.spdl")
    x.verify()

if __name__ == '__main__':
    basictest()


