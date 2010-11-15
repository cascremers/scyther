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
import os.path

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
    parser.add_option("-m","--max-protocols",type="int",dest="maxprotocols",default=3,
            help="Define maximum number of protocols in a multi-protocol attack.")

    parser.add_option("-r","--max-runs",type="int",dest="maxruns",default=4,
            help="Define maximum number of runs in the analysis.")

    parser.add_option("-T","--timeout",type="int",dest="timeout",default=600,
            help="Timeout in seconds for each analysis.")

    parser.add_option("-L","--limit",type="int",dest="limit",default=0,
            help="Limit the length of the list of protocols.")

    parser.add_option("-t","--typed",dest="defoptarray",default=[],action="append_const",const="--match=0",
            help="Verify protocols with respect to a typed model (-m 0)")
    parser.add_option("-b","--basic-types",dest="defoptarray",default=[],action="append_const",const="--match=1",
            help="Verify protocols with respect to basic type flaws only (-m 1)")
    parser.add_option("-u","--untyped",dest="defoptarray",default=[],action="append_const",const="--match=2",
            help="Verify protocols with respect to an untyped model (-m 2)")

    parser.add_option("-U","--init-unique",dest="defoptarray",default=[],action="append_const",const="--init-unique",
            help="Use Scythers --init-unique switch to filter out initiators talking to themselves.")
    parser.add_option("-E","--extravert",dest="defoptarray",default=[],action="append_const",const="--extravert",
            help="Use Scythers --extravert switch to filter out agents talking to themselves.")

    # Choice tree
    parser.add_option("-A","--all-types",dest="alltypes",default=False,action="store_true",
            help="Verify protocols with respect to all matching types")
    parser.add_option("","--self-communication",dest="selfcommunication",default=False,action="store_true",
            help="Explore self-communication effects.")

    # Misc
    parser.add_option("-D","--debug",dest="debug",default=False,action="store_true",
            help="Enable debugging features.")
    parser.add_option("-p","--plain",dest="plain",default=False,action="store_true",
            help="Ensure plain output, e.g., no progress bars.")

    return parser.parse_args()

#---------------------------------------------------------------------------

class Attack(object):

    def __init__(self,claim,mpalist):

        self.claim = claim
        self.mpalist = mpalist

    def protocol(self):
        return self.claim.protocol

    def mpashort(self):

        s = []
        for fn in self.mpalist:
            ptn = os.path.normpath(fn)
            (head,tail) = os.path.split(ptn)
            s.append(tail)

        return s

    def __str__(self):
        s = "(%s,%s)" % (self.claim.id, self.mpashort())
        return s

    def fullstr(self):
        s = "%s,%s" % (self.claim.id, self.mpalist)
        return s

    def __cmp__(self,other):
        s1 = self.fullstr()
        s2 = other.fullstr()
        if (s1 == s2):
            return 0
        else:
            if s1 < s2:
                return -1
            else:
                return 1


#---------------------------------------------------------------------------

def uniq(l):

    ll = []
    for x in l:
        if x not in ll:
            ll.append(x)
    return ll

#---------------------------------------------------------------------------

def MyScyther(protocollist,filt=None,options=[]):
    """
    Evaluate the composition of the protocols in protocollist.
    If there is a filter, i.e. "ns3,I1" then only this specific claim
    will be evaluated.
    """
    global OPTS

    s = Scyther.Scyther()

    # Standard
    opts = OPTS.defoptarray + options

    # Adding other command-line parameters (i.e. with arguments)
    opts.append("-T %i" % (int(OPTS.timeout)))
    opts.append("--max-runs=%i" % (int(OPTS.maxruns)))

    # arguments to call
    s.options = (" ".join(sorted(uniq(opts)))).strip()
    if OPTS.debug:
        print s.options

    for protocol in protocollist:
        s.addFile(protocol)
    s.verifyOne(filt)
    return s
    

def getCorrectIsolatedClaims(protocolset,options=[]):
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
    cpcount = 0
    for protocol in protocolset:
        # verify protocol in isolation
        s = MyScyther([protocol],options=options)
        # investigate the results
        goodprotocols.append(protocol)
        allfalse = True
        for claim in s.claims:
            if claim.okay:
                correctclaims.append((protocol,claim.id))
                allfalse = False
        count += 1
        if not allfalse:
            cpcount += 1
        if not OPTS.plain:
            pbar.update(count)
    if not OPTS.plain:
        pbar.finish()
    return (goodprotocols,correctclaims,cpcount)


def verifyMPAlist(mpalist,claimid,options=[]):
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
            FOUND.append(Attack(claim,mpalist))

            return False
    else:
        return True


def constructMPAlist(protocolset,claimid,mpalist,length,start,callback,options=[]):
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
    

def findMPA(protocolset,protocol,claimid,options=[]):
    """
    The protocol claim is assumed to be correct. When does it break?
    """
    global OPTS

    # First we examine 2-protocol attacks, and then increase the
    # number of parallel protocols if we don't find any attacks on the
    # claim.
    maxcount = OPTS.maxprotocols
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


def findAllMPA(protocolset,options=[],mpaoptions=[]):
    """
    Given a set of protocols, find multi-protocol attacks
    """

    global FOUND

    FOUND = []

    # Find all correct claims in each protocol
    (protocolset,correct,cpcount) = getCorrectIsolatedClaims(protocolset,options)
    print "Investigating %i correct claims in %i protocols." % (len(correct), cpcount)
    # For all these claims...
    if not OPTS.plain:
        widgets = ['Scanning for MPA attacks: ', Percentage(), ' ',
                   Bar(marker='#',left='[',right=']')
                   ]
        pbar = ProgressBar(widgets=widgets, maxval=len(correct))
        pbar.start()
    count = 0

    # Concatenate options but add space iff needed
    alloptions = options + mpaoptions

    for (protocol,claimid) in correct:
        # Try to find multi-protocol attacks
        findMPA(protocolset,protocol,claimid,options=alloptions)
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
    res = []
    for att in FOUND:
        pn = att.protocol()
        if pn not in mpaprots:
            mpaprots.append(pn)
        res.append(att)

    print "-" * 70
    print "Summary:"
    print
    print "We scanned %i protocols with options [%s]." % (len(protocolset),options)
    print "We found %i correct claims." % (len(correct))
    print "We then scanned combinations of at most %i protocols with options [%s]." % (OPTS.maxprotocols,alloptions)
    print "We found %i MPA attacks." % (len(FOUND))
    print "The attacks involve the claims of %i protocols." % (len(mpaprots))
    print "-" * 70
    print

    return res


def showDiff(reslist):
    """
    Show difference between (attacklist,descr) tuples in list
    """
    for i in range(0,len(reslist)-1):
        (al1,descr1) = reslist[i]
        (al2,descr2) = reslist[i+1]

        print "-" * 70
        print "Comparing the attacks for [%s] with [%s]:" % (descr1,descr2)
        print len(al1), len(al2)
        print repr(al1)
        print repr(al2)
        for a in al2:
            if a not in al1:
                print "New attack: %s" % (a)
        for a in al1:
            if a not in al2:
                print "[Strange] disappeared attack: %s" % (a)

        print "-" * 70
        print






def makeChoices():
    """
    Make choice grid.
    Later options should (intuitively) give more attacks.

    [ MPAonly, (text,switch)* ]
    """

    global OPTS, ARGS

    choices = []

    if OPTS.alltypes:
        
        choices.append([ False, \
                ("no type flaws",["--match=0"]), \
                ("basic type flaws",["--match=1"]), \
                ("all type flaws",["--match=2"]), \
                ])

    if OPTS.selfcommunication:

        choices.append([ True, \
                ("Disallow A-A",["--extravert"]), \
                ("Allow responder A-A",["--init-unique"]), \
                ("Allow A-A",[]) \
                ])

    return choices


def exploreTree( i, choices , l, options = [], mpaoptions = []):
    """
    Each choice[x] is an array again:

        MPAonly, (txt,arg)*
    """

    if i >= len(choices):
        return findAllMPA(l, options = options, mpaoptions = mpaoptions)

    mpaonly = choices[i][0]
    cl = choices[i][1:]

    res = []
    for (txt,arg) in cl:

        print "For choice %i, selecting options %s" % (i,txt)
        if mpaonly:
            o1 = []
            o2 = arg
        else:
            o1 = arg
            o2 = []
        res = res + exploreTree(i+1, choices, l, options = options + o1, mpaoptions = mpaoptions + o2)

    return res



def fullScan(l, options = [], mpaoptions = []):

    global OPTS

    if OPTS.limit > 0:
        l = l[:OPTS.limit]

    choices = makeChoices()
    if len(choices) == 0:
        """
        No choices, just evaluate
        """
        res = findAllMPA(l, options = options, mpaoptions = mpaoptions)

    else:
        exploreTree(0, choices, l, options = options, mpaoptions = mpaoptions)




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

    fullScan(l)



def main():
    global OPTS, ARGS

    (OPTS,ARGS) = parseArgs()
    bigTest()
    #simpleTest()


if __name__ == '__main__':
    main()


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
