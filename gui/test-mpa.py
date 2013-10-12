#!/usr/bin/env python
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


"""

Example script to show how to perform large-scale tests using the
Scyther Python API (contained in the Scyther subdirectory)

In this example, multi-protocol attack analysis is performed on a small
test set.

Author: Cas Cremers

"""

from Scyther import Scyther

from optparse import OptionParser, OptionGroup, SUPPRESS_HELP
import time
import os.path
import json

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
ALLMPA = []
ALLCLAIMS = []
INVOLVED = []
PROTFILETONAME = {}
PROTNAMETOFILE = {}
OPTS = None
ARGS = None
PICKLEDATA = set()


#---------------------------------------------------------------------------

def parseArgs():
    usage = "usage: %prog [options] [inputfile]" 
    description = "test-mpa.py is a test script to help with multi-protocol analysis."
    parser = OptionParser(usage=usage,description=description, version="%prog 2.0")

    group = OptionGroup(parser, "Bounding the search space")
    group.add_option("-m","--max-protocols",type="int",dest="maxprotocols",default=3,
            help="Define maximum number of protocols in a multi-protocol attack [3].")

    group.add_option("-r","--max-runs",type="int",dest="maxruns",default=4,
            help="Define maximum number of runs in the analysis [4].")

    group.add_option("-T","--timeout",type="int",dest="timeout",default=600,
            help="Timeout in seconds for each analysis [600].")

    group.add_option("-L","--limit",type="int",dest="limit",default=0,
            help="Limit the length of the list of protocols [None].")
    parser.add_option_group(group)

    group = OptionGroup(parser, "Matching type options")
    group.add_option("-t","--typed",dest="defoptarray",default=[],action="append_const",const="--match=0",
            help="Verify protocols with respect to a typed model (-m 0) [default]")
    group.add_option("-b","--basic-types",dest="defoptarray",default=[],action="append_const",const="--match=1",
            help="Verify protocols with respect to basic type flaws only (-m 1)")
    group.add_option("-u","--untyped",dest="defoptarray",default=[],action="append_const",const="--match=2",
            help="Verify protocols with respect to an untyped model (-m 2)")
    group.add_option("-A","--all-types",dest="alltypes",default=False,action="store_true",
            help="Verify protocols with respect to all matching types")
    parser.add_option_group(group)

    group = OptionGroup(parser, "Restricting self-communication")
    group.add_option("-U","--init-unique",dest="defoptarray",default=[],action="append_const",const="--init-unique",
            help="Use Scythers --init-unique switch to filter out initiators talking to themselves.")
    group.add_option("-E","--extravert",dest="defoptarray",default=[],action="append_const",const="--extravert",
            help="Use Scythers --extravert switch to filter out agents talking to themselves.")
    group.add_option("","--self-communication",dest="selfcommunication",default=False,action="store_true",
            help="Explore all self-communication restrictions (as MPA-only option).")
    parser.add_option_group(group)

    # Misc
    parser.add_option("","--pickle",dest="pickle",
            help="Do not invoke Scyther but write intended calls to a file with the given name.")   # action="store" and type="string" are defaults
    parser.add_option("-l","--latex",dest="latex",
            help="Output latex files with the given prefix.")   # action="store" and type="string" are defaults
    parser.add_option("-v","--verbose",dest="verbose",default=False,action="store_true",
            help="Be more verbose.")
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

    def claimid(self):
        return "%s" % (self.claim.id)

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


def powerset(s):
    """
    s is a set
    returns the powerset
    """
    pws = set([frozenset()])
    for el in s:
        # Double old powerset by adding its elements and also new ones
        for s2 in pws.copy():
            if len(s2) == 0:
                pws.add(frozenset([el]))
            else:
                pws.add(frozenset([el]).union(s2))
    return pws
    

#---------------------------------------------------------------------------

def MyScyther(protocollist,filt=None,options=[],checkpickle=True):
    """
    Evaluate the composition of the protocols in protocollist.
    If there is a filter, i.e. "ns3,I1" then only this specific claim
    will be evaluated.

    By default, when Pickling, no evaluation is done (checkpickle=True).
    Setting 'checkpickle' to False ignores this check and verifies anyway.
    """
    global OPTS
    global PICKLEDATA

    s = Scyther.Scyther()

    # Standard
    opts = OPTS.defoptarray + options

    # Cover for caching issue where no --match= option is given (default to 0)
    matchfound = False
    for opt in opts:
        if opt.startswith("--match="):
            matchfound = True
            break
    if not matchfound:
        opts.append("--match=0")

    # Adding other command-line parameters (i.e. with arguments)
    opts.append("-T %i" % (int(OPTS.timeout)))
    opts.append("--max-runs=%i" % (int(OPTS.maxruns)))

    # arguments to call
    s.options = (" ".join(sorted(uniq(opts)))).strip()
    if OPTS.debug:
        print s.options

    for protocol in sorted(protocollist):
        s.addFile(protocol)
    if checkpickle and OPTS.pickle:
        # Do not really verify! Just dump request if not already known
        if s.verifyOne(filt, checkKnown=True) == False:
            PICKLEDATA.add((tuple(sorted(protocollist)),s.options,filt))
    else:
        # Verify results
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
        widgets = ['Scanning for claims that are correct in isolation: ', SimpleProgress(), ' protocols (', Percentage(), ') ',
                   Bar(marker='#',left='[',right=']')
                   ]
        pbar = ProgressBar(widgets=widgets, maxval=len(protocolset))
        pbar.start()
    count = 0
    cpcount = 0
    for protocol in protocolset:
        # verify protocol in isolation
        s = MyScyther([protocol],options=options,checkpickle=False)
        # investigate the results
        goodprotocols.append(protocol)
        allfalse = True
        for claim in s.claims:
            global ALLCLAIMS
            global PROTFILETONAME
            global PROTNAMETOFILE

            if claim not in ALLCLAIMS:
                ALLCLAIMS.append(claim)

            if claim.okay:
                correctclaims.append((protocol,claim.id))
                allfalse = False

            PROTFILETONAME[protocol] = str(claim.protocol)
            PROTNAMETOFILE[str(claim.protocol)] = protocol

        count += 1
        if not allfalse:
            cpcount += 1
        if not OPTS.plain:
            pbar.update(count)

    if not OPTS.plain:
        pbar.finish()
    return (goodprotocols,correctclaims,cpcount)


def verifyProtList(protlist,claimid,options=[]):
    """
    Check attacks on this protocol list.
    Returns True if no attack ("correct") and False if an attack is found.
    """
    s = MyScyther(protlist,claimid,options)
    claim = s.getClaim(claimid)
    if claim:
        if not claim.okay:
            return False
    return True



def verifyProtSubSet(protlist,claimid,options=[]):
    """
    Check attacks on true subsets of this list.
    Note subsets must include the claim id
    """
    global OPTS

    ps = powerset(set(protlist))
    for s in ps:
        if (len(s) > 0) and (len(s) < len(protlist)):
            res = verifyProtList(list(s),claimid,options)
            if res == False:
                """
                If an attack is found we're actually done but for pickle we
                make an exception to generate all possible variants.
                """
                if not OPTS.pickle:
                    return False
    return True


def verifyMPAattack(mpalist,claimid,options=[]):
    """
    Check for Multi-Protocol Attacks on this protocol list.
    Returns True if no attack ("correct") and False if an MPA attack is found.

    First consider subsets, so if there is an attack there, don't consider others.
    """
    global OPTS

    res = verifyProtSubSet(mpalist,claimid,options)
    if res or OPTS.pickle:
        """
        Only really needed when no attack found but for pickle we make an
        exception to generate all possible variants.
        """
        return verifyProtList(mpalist,claimid,options)
    return True


def verifyMPAlist(mpalist,claimid,options=[]):
    """
    Check the existence of a multi-protocol attack in this context

    If an attack is found, we return False, otherwise True. This is
    needed for the iteration later.
    """
    global OPTS, ARGS

    if OPTS.debug:
        print time.asctime(), mpalist, claimid, options

    if not verifyMPAattack(mpalist,claimid,options):
        global FOUND
        global ALLFOUND
        global INVOLVED

        claim = claimidToClaim(claimid)

        # This is an MPA attack!
        if OPTS.debug:
            print "I've found a multi-protocol attack on claim %s in the context %s." % (claimid,str(mpalist))
        
        att = Attack(claim,mpalist)
        FOUND.append(att)
        ALLFOUND.append(att)

        inv = [claim.protocol]
        for fn in mpalist:
            global PROTFILETONAME
            inv.append(PROTFILETONAME[fn])

        for pn in inv:
            if pn not in INVOLVED:
                INVOLVED.append(pn)

        #return False

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


def foundToDicts(attacklist = []):
    """
    Turn a list of attacks into a more structured dict of dicts
    protocolname -> claimid -> P(attack)
    """
    res = {}
    for att in attacklist:
        pn = str(att.protocol())
        cl = att.claimid()

        if pn not in res.keys():
            res[pn] = {}
        if cl not in res[pn].keys():
            res[pn][cl] = set()
        res[pn][cl].add(att)
    return res


def findAllMPA(protocolset,options=[],mpaoptions=[]):
    """
    Given a set of protocols, find multi-protocol attacks
    """

    global FOUND
    global OPTS, ARGS
    global PROTNAMETOFILE
    global ALLCLAIMS

    FOUND = []

    # Find all correct claims in each protocol
    (protocolset,correct,cpcount) = getCorrectIsolatedClaims(protocolset,options)
    print "Investigating %i correct claims in %i protocols." % (len(correct), cpcount)

    mpaprots = []
    res = []

    if len(correct) == 0:
        print "Nothing to do."
        return res

    if OPTS.verbose:
        """
        When verbose, list correct claims in protocols
        """
        pmapclaims = {}
        for (protocol,claimid) in correct:
            if protocol not in pmapclaims.keys():
                pmapclaims[protocol] = set()
            pmapclaims[protocol].add(claimid)
        print "Protocols with correct claims:"
        if len(pmapclaims.keys()) == 0:
            print "  None."
        else:
            for pk in pmapclaims.keys():
                print "  %s, %s" % (pk, pmapclaims[pk])
        print
        left = set()
        for p in protocolset:
            if p not in pmapclaims.keys():
                left.add(p)
        print "Protocols with no correct claims:"
        if len(left) == 0:
            print "  None."
        else:
            for p in left:
                print "  %s" % (p)
        print

    # output of all claims (only if latex required)
    
    if OPTS.latex:
        clset = set()
        for claim in ALLCLAIMS:
            prot = str(claim.protocol)
            file = PROTNAMETOFILE[prot]
            clid = claim.id
            descr = claim.roledescribe()
            
            tup = (file,prot,clid,descr)
            clset.add(tup)

        fp = open("gen-%s-claims.txt" % (OPTS.latex),"w")

        fp.write("%% OPTS: %s\n" % OPTS)
        fp.write("%% ARGS: %s\n" % ARGS)

        for (file,prot,clid,descr) in sorted(clset):
            fp.write("%s; %s; %s; %s\n" % (file,prot,clid,descr))

        fp.close()

    # Latex output of protocols with correct claims
    if OPTS.latex:
        pmapclaims = {}
        for (protocol,claimid) in correct:
            if protocol not in pmapclaims.keys():
                pmapclaims[protocol] = set()
            pmapclaims[protocol].add(claimid)

        fp = open("gen-%s-correctclaims.tex" % (OPTS.latex),"w")

        fp.write("%% OPTS: %s\n" % OPTS)
        fp.write("%% ARGS: %s\n" % ARGS)

        fp.write("\\begin{tabular}{ll}\n")
        fp.write("Protocol & Claims \\\\\n")
        for protocol in sorted(pmapclaims.keys()):
            fp.write("%s & " % (PROTFILETONAME[protocol]))
            claims = sorted(pmapclaims[protocol])
            latexcl = set()
            for claimid in claims:
                claim = claimidToClaim(claimid)
                latexcl.add(claim.roledescribe())

            fp.write("; ".join(sorted(latexcl)))
            fp.write("\\\\\n")
        fp.write("\\end{tabular}\n")
        fp.close()

    # For all these claims...
    if not OPTS.plain:
        widgets = ['Scanning for MPA attacks: ', SimpleProgress(), ' claims (', Percentage(), ') ',
                   Bar(marker='#',left='[',right=']'),
                   ETA()
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
    for att in FOUND:
        pn = att.protocol()
        if pn not in mpaprots:
            mpaprots.append(pn)
        res.append(att)

    """
    Latex table of attacks

    TODO : map file names to protocol names, write out claim details

    TODO : remove main protocol from list (it's: "MPA attacks when run in parallel with")

    TODO : Check whether current tests stop after finding *one* MPA attack or whether they find *all*.

    """
    if OPTS.latex and not OPTS.pickle:
        fp = open("gen-%s-mpaattacks.tex" % (OPTS.latex),"w")

        fp.write("%% OPTS: %s\n" % OPTS)
        fp.write("%% ARGS: %s\n" % ARGS)

        fp.write("\\begin{tabular}{lll}\n")
        fp.write("Protocol & Claim & MPA attacks \\\\ \n")

        # Convert to more useful structure (maybe move one level up)
        res = foundToDicts(FOUND)

        """
        Scan per protocol in mpaprots (maybe sorted?)
        """
        for prot in sorted(res.keys()):
            """
            List claim and then attack scenarios (to some max?)
            """
            ltprot = prot
            for claimid in sorted(res[prot].keys()):

                firstclaim = True
                for att in sorted(res[prot][claimid]):

                    if firstclaim:

                        ltclaim = att.claim.roledescribe()
                        firstclaim = False

                    attl = att.mpalist
                    ltattacks = []
                    for attprot in attl:
                        if PROTFILETONAME[attprot] != att.claim.protocol:
                            ltattacks.append(PROTFILETONAME[attprot])

                    fp.write("%s & %s & %s \\\\ \n" % (ltprot,ltclaim,sorted(ltattacks)))

                    # Erase for cleaner table
                    ltprot = ""
                    ltclaim = ""

        fp.write("\\end{tabular}\n")
        fp.close()

    print "-" * 70
    print "Summary:"
    print
    print "We scanned %i protocols with options [%s]." % (len(protocolset),options)
    print "We found %i correct claims." % (len(correct))
    print "We then scanned combinations of at most %i protocols with options [%s]." % (OPTS.maxprotocols,alloptions)
    if OPTS.pickle:
        print "However, just precomputing now, hence we are not drawing any conclusions."
    else:
        print "We found %i MPA attacks." % (len(FOUND))
        print "The attacks involve the claims of %i protocols." % (len(mpaprots))
    print "-" * 70
    print

    return res


def claimidToClaim(claimid):
    """
    Return claim object given a claim id
    """
    global ALLCLAIMS

    for claim in ALLCLAIMS:
        if claim.id == claimid:
            return claim



def showDiff(reslist):
    """
    Show difference between (opts,mpaopts,attacklist) tuples in list
    """
    if len(reslist) == 0:
        print "Comparison list is empty"
        return

    (opt1,mpaopt1,al1) = reslist[0]
    print "-" * 70
    print "Base case: attacks for \n  [%s]:" % (opt1 + mpaopt1)
    print
    print len(al1)
    for a in al1:
        print "Base attack: %s" % (a)

    print "-" * 70
    print

    for i in range(0,len(reslist)-1):
        (opt1,mpaopt1,al1) = reslist[i]
        (opt2,mpaopt2,al2) = reslist[i+1]

        print "-" * 70
        print "Comparing the attacks for \n  [%s] with\n  [%s]:" % (opt1 + mpaopt1, opt2 + mpaopt2)
        print
        print len(al1), len(al2)
        for a in al2:
            if a not in al1:
                print "Added attack: %s" % (a)
        for a in al1:
            if a not in al2:
                print "Removed attack: %s" % (a)

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
        return [(options,mpaoptions,findAllMPA(l, options = options, mpaoptions = mpaoptions))]

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
    global ALLFOUND
    global ALLCLAIMS
    global INVOLVED
    global PROTNAMETOFILE
    global PROTFILETONAME

    ALLFOUND = []
    ALLCLAIMS = []
    INVOLVED = []

    if OPTS.limit > 0:
        l = l[:OPTS.limit]

    choices = makeChoices()
    if len(choices) == 0:
        """
        No choices, just evaluate
        """
        res = findAllMPA(l, options = options, mpaoptions = mpaoptions)

    else:
        lres = exploreTree(0, choices, l, options = options, mpaoptions = mpaoptions)
        if len(lres) > 1:
            if not OPTS.pickle:
                showDiff(lres)

    allprots = set()
    attprots = set()
    invprots = set()
    for att in ALLFOUND:
        attprots.add(str(att.protocol()))
    for cl in ALLCLAIMS:
        allprots.add(str(cl.protocol))
    for prot in INVOLVED:
        invprots.add(str(prot))

    if not OPTS.pickle:
        print "The bottom line: we found %i protocols with multi-protocol attacks from a set of %i protocols." % (len(attprots),len(allprots))
        print

        print "Multi-protocol attacks were found on:"
        for prot in sorted(list(allprots & attprots)):
            print "  %s" % (prot)
        print

        print "No multi-protocol attacks were found on these protocols, but they caused MPA attacks:"
        for prot in sorted(list((allprots - attprots) & invprots)):
            print "  %s" % (prot)
        print

        print "These protocols were not involved in any MPA attacks:"
        for prot in sorted(list((allprots - attprots) - invprots)):
            print "  %s\t[%s]" % (prot,PROTNAMETOFILE[prot])
        print




def bigTest():
    """
    Perform the tests as reported in the book.
    """
    import os

    global OPTS, ARGS

    l = []
    nl = []

    """
    Check for any given filenames
    """
    if len(ARGS) == 0:
        # No filenames given
        testpath = "Protocols/MultiProtocolAttacks/"
        fl = os.listdir(testpath)
        for fn in fl:
            if fn.endswith(".spdl"):
                nl.append(fn)

        # Prepend again the path
        l = []
        for fn in nl:
            l.append(testpath+fn)
    else:
        for fn in ARGS:
            l.append(fn)
        nl = l

    # Report list
    print "Performing multi-protocol analysis for the following protocols:", nl

    fullScan(l)



def main():
    global OPTS, ARGS, PICKLEDATA

    (OPTS,ARGS) = parseArgs()
    if OPTS.pickle:
        PICKLEDATA = set()

    bigTest()

    #simpleTest()

    if OPTS.pickle:
        pf = open(OPTS.pickle,"wa")
        for el in PICKLEDATA:
            json.dump(el,pf)
            pf.write("\n")
        pf.close()


if __name__ == '__main__':
    main()


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
