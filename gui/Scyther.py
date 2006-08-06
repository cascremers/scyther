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

        # Where is my executable?
        if sys.platform.startswith('win'):
            """ Windows """
            # TODO hardcoded for now, bad
            self.program = "c:\\Scyther.exe"
            if not os.path.isfile(self.program):
                print "I can't find the Scyther executable at %s" % (self.program)
        else:
            """ Non-windows """
            self.program = "scyther"

        self.options = ""
        self.spdl = None
        self.inputfile = None
        self.claims = None
        self.errors = None

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

        (stdin,stdout,stderr) = os.popen3(self.cmd)
        if self.spdl:
            stdin.write(self.spdl)
        stdin.close()

        # In the order below, or stuff breaks (hangs), as described at
        # http://mail.python.org/pipermail/python-dev/2000-September/009460.html
        #
        # TODO this is annoying: we would like to determine progress
        # from the error output (maybe this can also be done by flushing
        # the XML at certain points...)
        xmlinput = stdout.read()
        self.errors = stderr.readlines()
        
        # close
        stdout.close()
        stderr.close()

        print self.errors

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
    pw,pr = os.popen2("%s --help" % x.program)
    pw.close()
    print pr.read()
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


