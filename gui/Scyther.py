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
        self.inputfile = None
        self.claims = None

    def setInput(self,spdl):
        self.spdl = spdl
        self.inputfile = None

    def setFile(self,filename):
        self.inputfile = filename
        self.spdl = ""
        fp = open(filename,"r")
        for l in fp.readlines():
            self.spdl += l
        fp.close()

    def verify(self):

        # Run Scyther on temp file
        self.cmd = "%s --dot-output --xml-output --plain %s" % (self.program,self.options)

        if self.spdl:
            if self.inputfile:
                fp = open(self.inputfile,'r')
            else:
                # Write spdl to temp file
                fp = tempfile.NamedTemporaryFile()
                fp.write(self.spdl)
                fp.flush()
            self.cmd += " %s" % (fp.name)

        # If we are on windows, we don't get stderr. Maybe we need a
        # switch to enforce this.
        if sys.platform.startswith('linux'):
            cmdline = "%s 2>/dev/null" % (self.cmd)
        else:
            # Non-linux does not generate stderr anyway
            cmdline = "%s" % (self.cmd)

        print cmdline
        confirm("Run this command?")

        result = os.popen(cmdline)
        xmlinput = result.read()
        result.close()

        print xmlinput
        confirm("Is this the correct output?")

        if self.spdl:
            fp.close()

        xmlfile = StringIO.StringIO(xmlinput)
        reader = XMLReader.XMLReader()
        self.claims = reader.readXML(xmlfile)

        return self.claims

    def __str__(self):
        if self.claims:
            s = ""
            for cl in self.claims:
                s += str(cl) + "\n"
            return s
        else:
            return "Scyther has not been run yet."


def basicTest():
    # Some basic testing
    #if sys.platform.startswith('win'):
    #    print "Dir test"
    #    p = os.popen("dir")
    #    print p.read()
    #    print p.close()
    #    confirm("See the dir?")
   
    # Scyther
    x = Scyther()

    if sys.platform.startswith('win'):
        x.program = "Scyther.exe"
        if not os.path.isfile(x.program):
            print "I can't find the Scyther executable %s" % (x.program)
        else:
            p = os.popen("%s --help" % x.program)
            print p.read()
            confirm("Do you see the help?")

    x.setFile("ns3.spdl")
    x.verify()
    print x
    confirm("See the output?")

def simpleRun(args):
    x = Scyther()
    x.options = args
    x.verify()
    return x

if __name__ == '__main__':
    pars = sys.argv[1:]
    if len(pars) == 0:
        basicTest()
    else:
        print simpleRun(" ".join(pars))


