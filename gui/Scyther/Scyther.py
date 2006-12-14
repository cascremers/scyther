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
import Error
from Misc import *

#---------------------------------------------------------------------------

"""
Globals
"""

FirstCheck = True

#---------------------------------------------------------------------------

"""
The default path for the binaries is set in __init__.py in the (current)
directory 'Scyther'.
"""

def setBinDir(dir):
    global bindir

    bindir = dir

def getBinDir():
    global bindir

    return bindir

#---------------------------------------------------------------------------

def Check():
    """
    Various dynamic checks that can be performed before starting the
    backend.
    """

    global FirstCheck

    # First time
    if FirstCheck:
        """
        Perform any checks that only need to be done the first time.
        """
        FirstCheck = False

    # Every time
    
    # Check Scyther backend program availability
    program = getScytherBackend()
    CheckSanity(program)

#---------------------------------------------------------------------------

def CheckSanity(program):
    """
    This is where the existence is checked of the Scyther backend.
    """

    if not os.path.isfile(program):
        raise Error.BinaryError, program

#---------------------------------------------------------------------------

def getScytherBackend():
    # Where is my executable?
    #
    # Auto-detect platform and infer executable name from that
    #
    if "linux" in sys.platform:

        """ linux """
        scythername = "scyther-linux"

    # elif "darwin" in sys.platform:

    #     """ OS X """
    #     # Preferably, we test for architecture (PPC/Intel) until we
    #     # know how to build a universal binary
    #     scythername = "scyther-osx"

    elif sys.platform.startswith('win'):

        """ Windows """
        scythername = "scyther-w32.exe"

    else:

        """ Unsupported"""
        raise Error.UnknownPlatformError, sys.platform

    program = os.path.join(getBinDir(),scythername)
    return program


#---------------------------------------------------------------------------

class Scyther(object):
    def __init__ ( self):

        # Init
        self.program = getScytherBackend()
        self.spdl = None
        self.inputfile = None
        self.options = ""
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

    def doScytherCommand(self, spdl, args):
        """ 
        Run Scyther backend on the input
        
        Arguments:
            spdl -- string describing the spdl text
            args -- arguments for the command-line
        Returns:
            (output,errors)
            output -- string which is the real output
            errors -- string which captures the errors
        """

        if self.program == None:
            raise Error.NoBinaryError

        # Generate temporary files for the output
        # Requires Python 2.3 though.
        (fde,fne) = tempfile.mkstemp()  # errors
        (fdo,fno) = tempfile.mkstemp()  # output
        (fdi,fni) = tempfile.mkstemp()  # input

        # Write (input) file
        fhi = os.fdopen(fdi,'w+b')
        if spdl:
            fhi.write(spdl)
        fhi.close()

        # Generate command line for the Scyther process
        self.cmd = ""
        self.cmd += "\"%s\"" % self.program
        self.cmd += " --append-errors=%s" % fne
        self.cmd += " --append-output=%s" % fno
        self.cmd += " %s %s" % (self.options, args)
        if spdl:
            self.cmd += " %s" % fni

        # Start the process
        os.system(self.cmd)

        # reseek
        fhe = os.fdopen(fde)
        fho = os.fdopen(fdo)
        errors = fhe.read()
        output = fho.read()

        # clean up files
        fhe.close()
        fho.close()
        os.remove(fne)
        os.remove(fno)
        os.remove(fni)

        return (output,errors)

    def verify(self):
        """ Should return a list of results """
    
        # prepare arguments
        args = ""
        if self.xml:
            args += " --dot-output --xml-output --plain"
        args += " %s" % self.options

        # execute
        (output,errors) = self.doScytherCommand(self.spdl, args)
        self.run = True

        # process errors
        self.errors = []
        for l in errors.splitlines():
            # filter out any non-errors (say maybe only claim etc) and count
            # them.
            if not l.startswith("claim\t"):
                self.errors.append(l.strip())
        self.errorcount = len(self.errors)

        # process output
        self.output = output
        self.validxml = False
        self.claims = []
        if self.xml:
            if len(output) > 0:
                if output.startswith("<scyther>"):

                    # whoohee, xml
                    self.validxml = True

                    xmlfile = StringIO.StringIO(output)
                    reader = XMLReader.XMLReader()
                    self.claims = reader.readXML(xmlfile)

        # Determine what should be the result
        if self.xml:
            return self.claims
        else:
            return self.output

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
                if self.xml and self.validxml:
                    s = "Verification results:\n"
                    for cl in self.claims:
                        s += str(cl) + "\n"
                    return s
                else:
                    return self.output
        else:
            return "Scyther has not been run yet."

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
