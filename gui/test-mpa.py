#!/usr/bin/env python
"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007 Cas Cremers

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


"""

Example script to show how to perform large-scale tests using the
Scyther Python API (contained in the Scyther subdirectory)

In this example, multi-protocol attack analysis is performed on a small
test set.

Author: Cas Cremers

"""

from Scyther import Scyther

from optparse import OptionParser, SUPPRESS_HELP
import time

try:
    from progressbar import *
    PROGRESSBAR = True
except ImportError:
    from progressbarDummy import *
    PROGRESSBAR = False
    print """
Missing the progressbar library.

It can be downloaded from:

http://code.google.com/p/python-progressbar/

"""

FOUND = []
OPTS = None
ARGS = None


#---------------------------------------------------------------------------

def parseArgs():
    usage = "usage: %s [options] [inputfile]" % sys.argv[0]
    description = "test-mpa.py is a test script to help with multi-protocol analysis."
    parser = OptionParser(usage=usage,description=description)

    # command
    parser.add_option("-t","--typed",dest="types",default=None,action="store_const",const=[0],
            help="Verify protocols with respect to a typed model (-m 0)")
    parser.add_option("-b","--basic-types",dest="types",default=None,action="store_const",const=[1],
            help="Verify protocols with respect to basic type flaws only (-m 1)")
    parser.add_option("-u","--untyped",dest="types",default=None,action="store_const",const=[2],
            help="Verify protocols with respect to an untyped model (-m 2)")

    parser.add_option("-m","--max-protocols",type="int",dest="maxprotocols",default=3,
            help="Define maximum number of protocols in a multi-protocol attack.")

    parser.add_option("-T","--all-types",dest="types",default=None,action="store_const",const=[0,1,2],
            help="Verify protocols with respect to all matching types")

    parser.add_option("-U","--init-unique",dest="initunique",default=False,action="store_true",
            help="Use Scythers --init-unique switch to filter out initiators talking to themselves.")

    parser.add_option("-D","--debug",dest="debug",default=False,action="store_true",
            help="Enable debugging features.")

    parser.add_option("-p","--plain",dest="plain",default=False,action="store_true",
            help="Ensure plain output, e.g., no progress bars.")

    return parser.parse_args()

#---------------------------------------------------------------------------

def MyScyther(protocollist,filt=None,options=None):
    """
    Evaluate the composition of the protocols in protocollist.
    If there is a filter, i.e. "ns3,I1" then only this specific claim
    will be evaluated.
    """
    s = Scyther.Scyther()

    if (options == None) or (options == ""):
        # untyped matching
        s.options = "--match=2"
    else:
        s.options = options.strip() # Some cleanup of string (idiot's normalization)

    for protocol in protocollist:
        s.addFile(protocol)
    s.verifyOne(filt)
    return s
    

def getCorrectIsolatedClaims(protocolset,options=None):
    """
    Given a set of protocols, determine the correct claims when run in
    isolation.
    Returns a tuple, consisting of
    - a list of compiling protocols
    - a list of tuples (protocol,claimid) wich denote correct claims
    """
    correctclaims = []
    goodprotocols = []

    if not OPTS.plain:
        widgets = ['Scanning for claims that are correct in isolation: ', Percentage(), ' ',
                   Bar(marker='#',left='[',right=']')
                   ]
        pbar = ProgressBar(widgets=widgets, maxval=len(protocolset))
        pbar.start()
    count = 0
    for protocol in protocolset:
        # verify protocol in isolation
        s = MyScyther([protocol],options=options)
        # investigate the results
        goodprotocols.append(protocol)
        for claim in s.claims:
            if claim.okay:
                correctclaims.append((protocol,claim.id))
        count += 1
    return (goodprotocols,correctclaims)
        if not OPTS.plain:
            pbar.update(count)
    if not OPTS.plain:
        pbar.finish()


def verifyMPAlist(mpalist,claimid,options=None):
    """
    Verify the existence of an attack in this context

    If an attack is found, we return False, otherwise True. This is
    needed for the iteration later.
    """
    global OPTS, ARGS

    if OPTS.debug:
        print time.asctime(), mpalist, claimid, options

    s = MyScyther(mpalist,claimid,options)
    claim = s.getClaim(claimid)
    if claim:
        if not claim.okay:
            global FOUND

            # This is an MPA attack!
            if OPTS.debug:
                print "I've found a multi-protocol attack on claim %s in the context %s." % (claimid,str(mpalist))
            FOUND.append((claimid,mpalist))

            return False
    else:
        return True


def constructMPAlist(protocolset,claimid,mpalist,length,start,callback,options=None):
    """
    Append a list of parallel protocols, without duplicates,
    such that the added part is lexicographically ordered (from
    index 'start' in the protocol list)
    For each possible list, the function callback is called. If the
    callback returns true, iteration proceeds (returning true in the
    end), otherwise it aborts and returns false.
    """
    if len(mpalist) < length:
        # list is not long enough yet
        for pn in range(start,len(protocolset)):
            p = protocolset[pn]
            if p not in mpalist:
                if not constructMPAlist(protocolset,claimid,mpalist + [p],length,pn+1,callback,options=options):
                    return False
        return True
    else:
        # list is long enough: callback
        return callback(mpalist,claimid,options)
    

def findMPA(protocolset,protocol,claimid,maxcount=3,options=None):
    """
    The protocol claim is assumed to be correct. When does it break?
    """

    # First we examine 2-protocol attacks, and then increase the
    # number of parallel protocols if we don't find any attacks on the
    # claim.
    count = 2
    if len(protocolset) < maxcount:
        # we cannot have more protocols in parallel than there are
        # protocols.
        maxcount = len(protocolset)

    # the actual incremental search loop
    while count <= maxcount:
        constructMPAlist(protocolset,claimid,[protocol],count,0,verifyMPAlist,options)
        count += 1
    return None


def findAllMPA(protocolset,maxcount=3,options="",mpaoptions=""):
    """
    Given a set of protocols, find multi-protocol attacks
    """

    global FOUND

    FOUND = []

    # Find all correct claims in each protocol
    (protocolset,correct) = getCorrectIsolatedClaims(protocolset,options)
    print "Investigating %i correct claims." % (len(correct))
    # For all these claims...
    if not OPTS.plain:
        widgets = ['Scanning for MPA attacks: ', Percentage(), ' ',
                   Bar(marker='#',left='[',right=']')
                   ]
        pbar = ProgressBar(widgets=widgets, maxval=len(correct))
        pbar.start()
    count = 0

    # Concatenate options but add space iff needed
    alloptions = (options + " " + mpaoptions).strip()

    for (protocol,claimid) in correct:
        # Try to find multi-protocol attacks
        findMPA(protocolset,protocol,claimid,maxcount,options=alloptions)
        count += 1
        if not OPTS.plain:
            pbar.update(count)
    if not OPTS.plain:
        pbar.finish()

    """
    The below computation assumes protocol names are unique to files, but if
    they are not, some other errors should have been reported by the Scyther
    backend anyway (conflicting protocol definitions in MPA analysis).
    """
    mpaprots = []
    for (claimid,mpalist) in FOUND:
        pel = claimid.split(",")
        pn = pel[0]
        if pn not in mpaprots:
            mpaprots.append(pn)

    print "-" * 70
    print "Summary:"
    print
    print "We scanned %i protocols with options [%s]." % (len(protocolset),options)
    print "We found %i correct claims." % (len(correct))
    print "We then scanned combinations of at most %i protocols with options [%s]." % (maxcount,alloptions)
    print "We found %i MPA attacks." % (len(FOUND))
    print "The attacks involve the claims of %i protocols." % (len(mpaprots))
    print "-" * 70


def bigTest():
    """
    Perform the tests as reported in the book.
    """
    import os

    global OPTS, ARGS

    testpath = "Protocols/MultiProtocolAttacks/"
    fl = os.listdir(testpath)
    nl = []
    for fn in fl:
        if fn.endswith(".spdl"):
            nl.append(fn)

    # Report list
    print "Performing multi-protocol analysis for the following protocols:", nl

    # Prepend again the path
    l = []
    for fn in nl:
        l.append(testpath+fn)

    # Initialize mpa options
    mpaopts = ""

    if OPTS.initunique:
        mpaopts = (mpaopts + " --init-unique").strip()

    ### Simplified test setup
    #defopts = "--max-runs=3 -T 360"

    ### Full test setup
    #defopts = "--max-runs=4 -T 600"

    ### Full test setup with --init-unique
    defopts = "--max-runs=4 -T 600"
    maxcount = OPTS.maxprotocols

    if OPTS.types == None:
        OPTS.types = [0]

    if 0 in OPTS.types:
        # First typed
        print "Scanning without type flaws"
        findAllMPA(l,maxcount=maxcount,options = defopts + " --match=0", mpaoptions = mpaopts)
    if 1 in OPTS.types:
        # Basic type flaws
        print "Scanning for basic type flaws"
        findAllMPA(l,maxcount=maxcount,options = defopts + " --match=1", mpaoptions = mpaopts)
    if 2 in OPTS.types:
        # All type flaws
        print "Scanning for any type flaws"
        findAllMPA(l,maxcount=maxcount,options = defopts + " --match=2", mpaoptions = mpaopts)



def simpleTest():
    """
    Simple test case with a few protocols
    """

    l = ['nsl3-broken.spdl','ns3.spdl','nsl3.spdl']
    print "Performing multi-protocol analysis for the following protocols:", l
    print
    findAllMPA(l)
    print
    print "Analysis complete."


def main():
    global OPTS, ARGS

    (OPTS,ARGS) = parseArgs()
    bigTest()
    #simpleTest()


if __name__ == '__main__':
    main()


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
