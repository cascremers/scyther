#!/usr/bin/python
#
# Scyther interface
#

#---------------------------------------------------------------------------

""" Import externals """
import os
import os.path
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
            self.program = os.path.join("bin","Scyther.exe")
            if not os.path.isfile(self.program):
                print "I can't find the Scyther executable at %s" % (self.program)
        else:
            """ Non-windows """
            self.program = os.path.join("bin","scyther")

        # Init
        self.spdl = None
        self.inputfile = None
        self.claims = None
        self.errors = None
        self.errorcount = 0
        self.run = False
        self.output = None

        # defaults
        self.xml = True     # this results in a claim end, otherwise we simply get the output

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

    def addFile(self,filename):
        self.inputfile = None
        if not self.spdl:
            self.spdl = ""
        fp = open(filename,"r")
        for l in fp.readlines():
            self.spdl += l
        fp.close()

    def verify(self):

        # Run Scyther on temp file
        self.cmd = self.program
        if self.xml:
            self.cmd += " --dot-output --xml-output --plain"
        self.cmd += " " + self.options

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
        output = stdout.read()
        errlines = stderr.readlines()

        # filter out any non-errors (say maybe only claim etc) and count
        # them.
        self.errors = []
        for l in errlines:
            if not l.startswith("claim\t"):
                self.errors.append(l.strip())

        self.errorcount = len(self.errors)
        
        # close
        stdout.close()
        stderr.close()

        if self.xml:
            if len(output) > 0:
                xmlfile = StringIO.StringIO(output)
                reader = XMLReader.XMLReader()
                self.claims = reader.readXML(xmlfile)
            else:
                # no output...
                self.claims = []
            result = self.claims
        else:
            self.output = output
            result = self.output

        self.run = True
        return result

    def getClaim(self,claimid):
        if self.claims:
            for cl in self.claims:
                if cl.id == claimid:
                    return cl
        return None

    def __str__(self):
        if self.run:
            if self.errorcount > 0:
                return "%i errors:\n%s" % (self.errorcount, "\n".join(self.errors))
            else:
                if self.xml:
                    s = "Claim results:\n"
                    for cl in self.claims:
                        s += str(cl) + "\n"
                    return s
                else:
                    return self.output
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
    #
    print "I don't know what to test now."
   

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


