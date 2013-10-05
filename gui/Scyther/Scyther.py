#!/usr/bin/python
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
try:
    import hashlib
    HASHLIB = True
except ImportError:
    HASHLIB = False
    pass

#---------------------------------------------------------------------------

""" Import scyther components """
import XMLReader
import Error
import Claim
from Misc import *

#---------------------------------------------------------------------------

"""
Globals
"""

FirstCheck = True

#---------------------------------------------------------------------------

"""
Get current directory (for this file)
"""
def getMyDir():
    return os.path.dirname( os.path.realpath( __file__ ) )

"""
The default path for the binaries is the current one.
"""
def getBinDir():
    return getMyDir()

"""
Return Cache prefix path
Returns None if not existent
"""
def getCacheDir():
    
    tmpdir = None

    # Check if user chose the path
    cachedirkey = "SCYTHERCACHEDIR"
    if cachedirkey in os.environ.keys():
        tmpdir = os.environ[cachedirkey]
        if tmpdir == "":
            # Special value: if the variable is present, but equals the empty string, we disable caching.
            return None
    else:
        # Otherwise take from path
        tmpdir = tempfile.gettempdir()
    
    # If not none, append special name
    if tmpdir != None:
        tmpdir = os.path.join(tmpdir,"Scyther-cache")

    return tmpdir

    

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

def EnsureString(x,sep=" "):
    """
    Takes a thing that is either a list or a string.
    Turns it into a string. If it was a list, <sep> is inserted, and the
    process iterats.

    TODO does not accept unicode yet, that is something that must be
    handled to or we run into wxPython problems eventually.
    """
    if type(x) is str:
        return x

    elif type(x) is list:
        newlist = []
        for el in x:
            newlist.append(EnsureString(el,sep))
        return sep.join(newlist)

    else:
        raise Error.StringListError, x


#---------------------------------------------------------------------------

def getScytherBackend():
    # Where is my executable?
    #
    # Auto-detect platform and infer executable name from that
    #
    if "linux" in sys.platform:

        """ linux """
        scythername = "scyther-linux"

    elif "darwin" in sys.platform:

        """ OS X """
        scythername = "scyther-mac"

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
        self.filenames = []
        self.options = ""
        self.claims = None
        self.errors = None
        self.errorcount = 0
        self.warnings = None
        self.run = False
        self.output = None
        self.cmd = None

        # defaults
        self.xml = True     # this results in a claim end, otherwise we simply get the output

    def setInput(self,spdl):
        self.spdl = spdl
        self.inputfile = None
        self.guessFileNames()

    def setFile(self,filename):
        self.inputfile = filename
        self.filenames = [self.inputfile]
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
        self.guessFileNames()

    def guessFileNames(self,spdl=None):
        """
        Try to extract filenames (well, actually, protocol names) sloppily from some spdl script.

        There are two modes:

        [init] : If the spdl parameter is empty or None, we reset the filenames and extract from self.spdl
        [add]  : If the spdl parameter is non-empty, add the extracted filenames to an existing list

        """

        if (spdl == None) or (len(spdl) == 0):
            spdl = self.spdl
            if spdl == None:
                spdl = ""
            self.filenames = []

        for sl in spdl.splitlines():
            l = sl.strip()
            prefix = "protocol "
            postfix = "("
            x = l.find(prefix)
            if x >= 0:
                # The prefix occurs
                y = l.find(postfix,x+len(prefix))
                if y >= 0:
                    gn = l[x+len(prefix):y]
                    # check for helper protocols
                    if not gn.startswith("@"):
                        if gn not in self.filenames:
                            self.filenames.append(gn)

    def addArglist(self,arglist):
        for arg in arglist:
            self.options += " %s" % (arg)

    def doScytherCommand(self, spdl, args, checkKnown=False, storePopen=None):
        """
        Cached version of the 'real' below

        TODO: CC: One possible problem with the caching is the side-effect, e.g., scyther writing to specific named output files. These are not
        captured in the cache. I don't have a good solution for that yet.
        """
        global HASHLIB

        # Can we use the cache?
        canCache = False
        if HASHLIB:
            cacheDir = getCacheDir()
            if cacheDir != None:
                canCache = True
        else:
            cacheDir = None

        # If we cannot use the cache, we either need to compute or, if checking for cache presense,...
        if not canCache:
            if checkKnown == True:
                # not using the cache, so we don't have it already
                return False
            else:
                # Need to compute
                return self.doScytherCommandReal(spdl,args, storePopen=storePopen)

        # Apparently we are supporsed to be able to use the cache
        m = hashlib.sha256()
        if spdl == None:
            m.update("[spdl:None]")
        else:
            m.update(spdl)
        if args == None:
            m.update("[args:None]")
        else:
            m.update(args)

        uid = m.hexdigest()

        # Split the uid to make 256 subdirectories with 256 subdirectories...
        prefixlen = 2
        uid1 = uid[:prefixlen]
        uid2 = uid[prefixlen:prefixlen+2]
        uid3 = uid[prefixlen+2:]

        # Possibly we could also decide to store input and arguments in the cache to analyze things later

        # Construct: cachePath/uid1/uid2/...
        path = os.path.join(cacheDir,uid1,uid2)
        name1 = "%s.out" % (uid3)
        name2 = "%s.err" % (uid3)

        fname1 = os.path.join(path, name1)
        fname2 = os.path.join(path, name2)

        try:
            """
            Try to retrieve the result from the cache
            """
            fh1 = open(fname1,"r")
            out = fh1.read()
            fh1.close()
            fh2 = open(fname2,"r")
            err = fh2.read()
            fh2.close()
            if checkKnown == True:
                # We got to here, so we have it
                return True
            else:
                # Not checking cache, we need the result
                return (out,err)
        except:
            pass

        """
        Something went wrong, do the real thing and cache afterwards
        """
        if checkKnown == True:
            # We were only checking, abort
            return False

        (out,err) = self.doScytherCommandReal(spdl,args, storePopen=storePopen)

        try:
            # Try to store result in cache
            ensurePath(path)

            fh1 = open(fname1,"w")
            fh1.write(out)
            fh1.close()

            fh2 = open(fname2,"w")
            fh2.write(err)
            fh2.close()
        except:
            pass

        return (out,err)


    def doScytherCommandReal(self, spdl, args, storePopen=None):
        """ 
        Run Scyther backend on the input
        
        Arguments:
            spdl -- string describing the spdl text
            args -- arguments for the command-line
            storePopen -- callback function to register Popen objects (used for process kill by other threads)
        Returns:
            (output,errors)
            output -- string which is the real output
            errors -- string which captures the errors
        """

        if self.program == None:
            raise Error.NoBinaryError

        # Sanitize input somewhat
        if spdl == "":
            # Scyther hickups on completely empty input
            spdl = "\n"

        # Extract filenames for error reporting later
        self.guessFileNames(spdl=spdl)

        # Generate temporary files for the output.
        # Requires Python 2.3 though.
        (fde,fne) = tempfile.mkstemp()  # errors
        (fdo,fno) = tempfile.mkstemp()  # output
        if spdl:
            (fdi,fni) = tempfile.mkstemp()  # input

            # Write (input) file
            fhi = os.fdopen(fdi,'w+b')
            fhi.write(spdl)
            fhi.close()

        # Generate command line for the Scyther process
        self.cmd = ""
        self.cmd += "\"%s\"" % self.program
        self.cmd += " --append-errors=%s" % fne
        self.cmd += " --append-output=%s" % fno
        self.cmd += " %s" % args
        if spdl:
            self.cmd += " %s" % fni

        # Only for debugging, really
        ##print self.cmd

        # Start the process
        safeCommand(self.cmd, storePopen=storePopen)

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
        if spdl:
            os.remove(fni)

        return (output,errors)

    def sanitize(self):
        """ Sanitize some of the input """
        self.options = EnsureString(self.options)

    def verify(self,extraoptions=None,checkKnown=False,storePopen=None):
        """ Should return a list of results """
        """ If checkKnown == True, we do not call Scyther, but just check the cache, and return True iff the result is in the cache """

        # Cleanup first
        self.sanitize()
    
        # prepare arguments
        args = ""
        if self.xml:
            args += " --dot-output --xml-output --plain"
        args += " %s" % self.options
        if extraoptions:
            # extraoptions might need sanitizing
            args += " %s" % EnsureString(extraoptions)

        # Are we only checking the cache?
        if checkKnown == True:
            return self.doScytherCommand(self.spdl, args, checkKnown=checkKnown, storePopen=storePopen)

        # execute
        (output,errors) = self.doScytherCommand(self.spdl, args, storePopen=storePopen)
        self.run = True

        # process errors
        self.errors = []
        self.warnings = []
        for l in errors.splitlines():
            line = l.strip()
            if len(line) > 0:
                # filter out any non-errors (say maybe only claim etc) and count
                # them.
                if line.startswith("claim\t"):
                    # Claims are lost, reconstructed from the XML output
                    pass
                elif line.startswith("warning"):
                    # Warnings are stored seperately
                    self.warnings.append(line)
                else:
                    # otherwise it is an error
                    self.errors.append(line)

        self.errorcount = len(self.errors)
        if self.errorcount > 0:
            raise Error.ScytherError(self.errors,filenames=self.filenames,options=self.options)

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

    def verifyOne(self,cl=None,checkKnown=False,storePopen=None):
        """
        Verify just a single claim with an ID retrieved from the
        procedure below, 'scanClaims', or a full claim object

        If checkKnown is True, return if the result is already known (but never recompute).
        """
        if cl:
            # We accept either a claim or a claim id
            if isinstance(cl,Claim.Claim):
                cl = cl.id
            return self.verify("--filter=%s" % cl, checkKnown=checkKnown,storePopen=storePopen)
        else:
            # If no claim, then its just normal verification
            return self.verify(checkKnown=checkKnown,storePopen=storePopen)

    def scanClaims(self):
        """
        Retrieve the list of claims. Of each element (a claim), claim.id
        can be passed to --filter=X or 'verifyOne' later.
        A result of 'None' means that some errors occurred.
        """
        self.verify("--scan-claims")
        if self.errorcount > 0:
            return None
        else:
            self.validxml = False   # Signal that we should not interpret the output as XML
            return self.claims

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

#---------------------------------------------------------------------------

def GetClaims(filelist, filterlist=None):
    """
    Given a list of file names in filelist,
    returns a dictionary of filenames to lists claim names.
    Filenames which yielded no claims are filtered out.
    
    Filterlist may be None or a list of claim names (Secret, SKR, Niagree etc).
    """

    dict = {}
    for fname in filelist:
        try:
            sc = Scyther()
            sc.setFile(fname)
            l = sc.scanClaims()
            if l != None:
                cl = []
                for claim in l:
                    if filterlist == None:
                        cl.append(claim.id)
                    else:
                        if claim.claimtype in filterlist:
                            cl.append(claim.id)
                dict[fname] = cl
        except:
            pass
    return dict

#---------------------------------------------------------------------------

def FindProtocols(path="",filterProtocol=None):
    """
    Find a list of protocol names

    Note: Unix only! Will not work under windows.
    """

    import commands

    cmd = "find %s -iname '*.spdl'" % (path)
    plist = commands.getoutput(cmd).splitlines()
    nlist = []
    for prot in plist:
        if filterProtocol != None:
            if filterProtocol(prot):
                nlist.append(prot)
        else:
            nlist.append(prot)
    return nlist

#---------------------------------------------------------------------------

def GetInfo(html=False):
    """
    Retrieve a tuple (location,string) with information about the tool,
    retrieved from the --expert --version data
    """

    program = getScytherBackend()
    arg = "--expert --version"
    sc = Scyther()
    (output,errors) = sc.doScytherCommand(spdl=None, args=arg)
    if not html:
        return (program,output)
    else:
        sep = "<br>\n"
        html = "Backend: %s%s" % (program,sep)
        for l in output.splitlines():
            l.strip()
            html += "%s%s" % (l,sep)
        return html


def GetLicense():
    """
    Retrieve license information.
    """

    program = getScytherBackend()
    arg = "--license"
    sc = Scyther()
    (output,errors) = sc.doScytherCommand(spdl=None, args=arg)
    return output


#---------------------------------------------------------------------------

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
