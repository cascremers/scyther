#!/usr/bin/python
"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2009 Cas Cremers

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

In this example, adversary model analysis.

Author: Cas Cremers

"""

import commands
import sys

from Scyther import *
try:
	from progressbar import *
	PROGRESSBAR = True
except ImportError:
	PROGRESSBAR = False
	print """
Missing the progressbar library.

It can be downloaded from:

http://code.google.com/p/python-progressbar/

"""
	sys.exit()

CACHEFILE = "verification-result-cache.tmp"   # Filename of cache
SHOWPATH = False    # Switch to true to show paths in the graph
#DEFAULTARGS = "--max-runs=7 --extravert"       ### If you're picky and have time. The results are the same, by the way.
DEFAULTARGS = "--max-runs=4"
DEFAULTARGS += " -T 300"         # Timeout after 5 minutes 
DEFAULTARGS += " --prune=1"     # Stop at first attack
ALLCORRECT = True   # Require all claims to be correct of the protocol in prev. node for counterexample
BRIEF = False
FAST = True    # True means Skip intermediate graph drawing

SUMMARYDB = {}      # prot -> delta
SUMMARYALL = False  # Delta's in all or in some contexts?
ACLMAX = 10         # After 10 we give up for the nodes
SCANERRORS = False  # Scan for arrows with no counterexamples

CALLSCYTHER = True  # After exit, make sure we don't call Scyther anymore.

DEBUG = False

CACHE = None
DB = {} # Model.dbkey -> (fname,claimid)*
FCD = {}
FCDN = 0
FCDX = 0
FCDS = 0
DRAWGRAPH = True
DOTABBREVS = {}

RESTRICTEDMODELS = None # No restricted model set
FILTER = None

SECMODELMIN = None
SECMODELMAX = None

SECMODELTRAVERSE = None     # Special list for optimal traversal
SECMODELFULL = None         # Special list for unrestricted traversal

"""
Names of PDF output files
"""
GRAPHPSH = "protocol-security-hierarchy"
GRAPHAMH = "adversary-model-hierarchy"
GRAPHCH = "combined-hierarchy-claimdetails"

def debugging():
    global DEBUG

    return DEBUG

def InitRestricted(models=None):
    """
    If we want restricted models, do so here.
    """
    global RESTRICTEDMODELS
    global SECMODELMIN, SECMODELMAX

    SECMODELMIN = SecModel()
    SECMODELMAX = SecModel("max")

    RESTRICTEDMODELS = None #   default

    external = SecModel()
    external.setName("EXT")

    # internal: notgroup
    internal = external.copy()
    internal.vector[0] = 1     
    internal.setName("INT")

    # kci: notgroup actor
    kci = external.copy()
    kci.vector[1] = 1
    kci.setName("CA")

    # bpr2000: skr
    bpr2000 = external.copy()
    bpr2000.vector[3] = 1
    bpr2000.setName("BPR")
    
    # br9395: notgroup skr
    br9395 = bpr2000.copy()
    br9395.vector[0] = 1
    br9395.setName("BR")
    
    # pfs: notgroup after
    pfs = external.copy()
    pfs.vector[2] = 3
    pfs.setName("AF")

    # wpfs: notgroup aftercorrect
    wpfs = pfs.copy()
    wpfs.vector[2] = 2
    wpfs.setName("AFC")

    # ck2001: notgroup after skr ssr
    ck2001 = pfs.copy()
    ck2001.union(internal)
    ck2001.vector[3] = 1
    ck2001.vector[4] = 2
    ck2001.setName("CK")

    # ck2001hmqv: notgroup aftercorrect skr ssr
    ck2001hmqv = ck2001.copy()
    ck2001hmqv.vector[1] = 1    # KCI
    ck2001hmqv.vector[2] = 2    # aftercorrect
    ck2001hmqv.setName("CKw")

    # eck: notgroup actor rnsafe skr rnr
    eck = kci.copy()
    eck.union(internal)
    eck.vector[2] = 1
    eck.vector[3] = 1
    eck.vector[5] = 1
    eck.setName("eCK")

    # eckalt: notgroup actor after skr rnr ssr
    eckalt = eck.copy()
    eckalt.vector[2] = 2
    eckalt.setName("eCK-alt")

    # eckplus: notgroup actor rnsafe skr rnr ssr
    eckplus = eck.copy()
    eckplus.vector[4] = 2
    eckplus.setName("eCK+")

    # RNR variants of SSR filters
    ck2001rnr = ck2001.copy()
    ck2001rnr.vector[4] = 1
    ck2001rnr.setName("CK-rnr")

    ck2001hmqvrnr = ck2001hmqv.copy()
    ck2001hmqvrnr.vector[4] = 1
    ck2001hmqvrnr.setName("CKw-nr")

    # eckssr: SSR variant of eCK
    eckssr = kci.copy()
    eckssr.vector[5] = 2
    eckssr.setName("eCK-ssr")

    RESTRICTEDMODELS = [eck, eckalt,ck2001rnr,ck2001hmqvrnr]    # To compare equal choice for RNR/SSR

    # append maximum
    max = external.copy()
    for m in RESTRICTEDMODELS:
        max.union(m)
    if max not in RESTRICTEDMODELS:
        RESTRICTEDMODELS.append(max)

    RESTRICTEDMODELS = [eckssr, ck2001,ck2001hmqv]      # To compare equal choice for RNR/SSR
    RESTRICTEDMODELS = [eck, ck2001hmqvrnr,ck2001rnr]   # Triangle restriction
    RESTRICTEDMODELS = [eck, ck2001hmqv,ck2001,ck2001hmqvrnr,ck2001rnr]         # Triangle restriction but allow state-reveal too

    #RESTRICTEDMODELS = None #   default
    if models == "CSF09":
        RESTRICTEDMODELS = [external, internal, kci, wpfs, pfs, bpr2000, br9395, ck2001hmqv, ck2001, eck]   # As in paper
    else:
        RESTRICTEDMODELS = None

    # Report
    reportModels(RESTRICTEDMODELS)


def reportModels(models):
    """
    Show a table analog to the one in the paper
    """

    ### DISABLED FOR NOW
    return

    if len(models) == 0:
        return
    # Header
    st = ""
    for x in range(0,models[0].length):
        st += "%i\t" % (x)
    print st
    print "-" * (8 * models[0].length)

    # Each model now
    for model in models:
        st = ""
        for x in range(0,model.length):
            st += "%i\t" % (model.vector[x])
        st += "%s\t(%s)" % (model.shortname(),model.dotkey())
        print st

    print "-" * (8 * models[0].length)


def fsort(f,a,b):
    """
    Silly helper function to help with sorting on a function base.
    """
    if f(a) > f(b):
        return 1
    elif f(a) < f(b):
        return -1
    else:
        return 0


class SecModel(object):

    def __init__(self,minmax=None,unrestricted=False):

        axis0 = ["--LKRnotgroup=0","--LKRnotgroup=1"]
        axis1 = ["","--LKRactor=1"]
        axis2 = ["","--LKRrnsafe=1","--LKRaftercorrect=1","--LKRafter=1"]
        axis3 = ["","--SKR=1"]
        axis4 = ["","--SSRfilter=1","--SSR=1"]
        axis5 = ["","--RNR=1"]

        #axis1 = ["--LKRnotgroup=1"]

        self.axes = [axis0,axis1,axis2,axis3,axis4,axis5]
        self.length = len(self.axes)

        if minmax == "max" or minmax == True:
            self.setMax(unrestricted=unrestricted)
        else:
            self.setMin(unrestricted=unrestricted)

        self.name=None


    def setName(self,name):

        self.name = name


    def ax(self,ax):
        """
        Yield max+1 of the axis
        """
        return len(self.axes[ax])


    def countTypes(self,all=False):
        """
        Give the number of possible adversary types
        """
        global RESTRICTEDMODELS

        if (all == True) or (RESTRICTEDMODELS == None):
            count = 1
            for i in range(0,self.length):
                count = count * self.ax(i)
            return count
        else:
            return len(RESTRICTEDMODELS)


    def checkSane(self,correct=False):
        """
        Makes a thing sane if correct==True

        We always assume 0 and max-1 are allowed for all vectors in all cases
        (empty model, max model)

        returns true if it was sane (and hence is surely unchanged)
        """
        global RESTRICTEDMODELS

        if RESTRICTEDMODELS == None:
            sane = True
            for i in range(0,self.length):
                # Ensure within normal range
                if self.vector[i] < 0:
                    if correct:
                        self.vector[i] = 0
                    sane = False
                elif self.vector[i] >= self.ax(i):
                    if correct:
                        self.vector[i] = self.ax(i) - 1
                    sane = False
                # Model particulars
                if (i == 2) and (self.vector[i] == 1):
                    if self.vector[5] == 0:
                        # Funny case: No RNR, but want to use rnsafe. Then
                        # it's equal to aftercorrect.
                        if correct:
                            self.vector[i] = 2
                        sane = False
            return sane
        else:
            assert(correct == False)

            return (self in RESTRICTEDMODELS)

    def setMin(self,unrestricted=False):
        global RESTRICTEDMODELS

        if (RESTRICTEDMODELS == None) or (unrestricted == True):
            self.vector = []
            for i in range(0,self.length):
                self.vector.append(0)
        else:
            RESTRICTEDMODELS[0].copy(tomodel=self)


    def setMax(self,unrestricted=False):
        global RESTRICTEDMODELS

        if (RESTRICTEDMODELS == None) or (unrestricted == True):
            self.vector = []
            for i in range(0,self.length):
                self.vector.append(self.ax(i)-1)
            self.checkSane(True)
        else:
            RESTRICTEDMODELS[-1].copy(tomodel=self)

    def describe(self,i):
        """
        Turn vector i into a parameter name.
        """
        s = self.axes[i][self.vector[i]]
        if s.endswith("=1"):
            return s[2:-2]
        return ""

    def enscribe(self,dbkey):
        """
        Reverts describe, i.e. sets the model to the descriptive name
        used e.g. in the cache.

        That is, given a dbkey, it sets the vector.
        """
        elements = dbkey.split("_")
        for i in range(0,self.length):
            # Cover vector[i]
            self.vector[i] = 0
            for y in range(0,len(self.axes[i])):
                # is it equal to the y thing?
                vecstr = self.axes[i][y]
                if vecstr.startswith("--") and vecstr.endswith("=1"):
                    # It's a triggered option, for sure
                    if vecstr[2:-2] in elements:
                        # Override previous
                        self.vector[i] = y
        return

    def shortname(self,unknown="???"):
        """
        Yield abbreviation
        """
        global RESTRICTEDMODELS

        pref = ""
        if RESTRICTEDMODELS != None:
            try:
                i = RESTRICTEDMODELS.index(self)
                xn = RESTRICTEDMODELS[i].name
                if xn != None:
                    return xn
            except:
                pass
        return unknown

    def __str__(self,sep=" ",empty="External",display=False,sort=False):
        """
        Yield string
        """

        pref = ""
        if display == True:
            pref = self.shortname(unknown="")
            if pref != "":
                pref += "\\n"

        sl = []
        for i in range(0,self.length):
            x = self.describe(i)
            if len(x) > 0:
                sl.append(x)
        if sort == True:
            sl.sort()
        if sl == []:
            return pref + empty
        else:
            return pref + sep.join(sl)

    def display(self):
        return self.__str__(display=True)

    def options(self):
        sl = []
        for i in range(0,self.length):
            sl.append(self.axes[i][self.vector[i]])
        return " ".join(sl)

    def dotkey(self):
        return self.__str__(sep="_",empty="None")

    def dbkey(self):
        return self.__str__(sep="_",empty="None",sort=True)

    def shortornot(self):
        """
        Short if possible
        """
        USTR = "???"
        xn = self.shortname(unknown=USTR)
        if xn == USTR:
            return (False,str(self))
        else:
            return (True,xn)

    def __cmp__(self,other):
        if other != None:
            if self.vector == other.vector:
                return 0
        return 1

    def weakerthan(self,other,direction=1):
        if direction >= 0:
            a = self
            b = other
        else:
            a = other
            b = self
        for i in range(0,a.length):
            if not (a.vector[i] <= b.vector[i]):
                return False
        return True

    def copy(self,tomodel=None):
        """
        Make a copy
        """
        if tomodel == None:
            tomodel = SecModel()
        tomodel.vector = []
        for i in range(0,self.length):
            tomodel.vector.append(self.vector[i])
        return tomodel

    def nextLinear(self):
        for i in range(0,self.length):
            
            while True:
                index = self.vector[i]
                if index >= self.ax(i)-1:
                    # overflow case coming up
                    self.vector[i] = 0
                    # Proceed to next digit anyway, this is sane
                    break
                else:
                    # no overflow, do it
                    self.vector[i] = self.vector[i]+1
                    if self.checkSane(False):
                        return self
                    # not sane, continue to increase
        return None

    def next(self,unrestricted=False):
        """
        Increase a given model, or return None when done
        """
        global RESTRICTEDMODELS

        if (RESTRICTEDMODELS == None) or (unrestricted == True):
            return self.nextLinear()
        else:
            i = RESTRICTEDMODELS.index(self)
            if i == len(RESTRICTEDMODELS) - 1:
                return None
            else:
                return RESTRICTEDMODELS[i+1]

    def getDir(self,direction,all=False):
        """
        Return a list of tuples (model,deltadescr)

        For RESTRICTEDMODELS == None or all==True, we have that each
        returned model is a new SecModel object that differs only in a
        single axis.
        """
        
        global RESTRICTEDMODELS

        others = []
        if (RESTRICTEDMODELS == None) or (all == True):
            # First we pick out all next ones
            for i in range(0,self.length):

                ctd = True
                ldir = direction
                while ctd == True:
                    ctd = False
                    index = self.vector[i]
                    index2 = index + ldir
                    if (index2 >=0 ) and (index2 < self.ax(i)):
                        model2 = self.copy()
                        model2.vector[i] = index2
                        if model2.checkSane(False):
                            newd = (model2,SecDelta(self,model2))
                            if newd not in others:
                                others.append(newd)
                        else:
                            if ldir > 0:
                                ldir += 1
                            else:
                                ldir -= 1
                            ctd = True

        else:
            mlist = []
            for model2 in RESTRICTEDMODELS:
                if not (model2 == self):
                    if self.weakerthan(model2,direction):
                        newd = (model2,SecDelta(self,model2))
                        if newd not in others:
                            others.append(newd)
                        if model2 not in mlist:
                            mlist.append(model2)
            # Then we pick out the minimal elements of these
            minimals = getMaxModels(mlist,direction=-direction)
            filtered = []
            for (model,delta) in others:
                if model in minimals:
                    filtered.append((model,delta))
            others = filtered

        return others

    def getLowers(self,all=False):
        return self.getDir(-1,all=all)

    def getHighers(self,all=False):
        return self.getDir(1,all=all)

    def isProtocolCorrect(self,protocol):
        """
        Is this protocol correct in this model?
        """
        global DRAWGRAPH
        global FCD

        for claimid in FCD[protocol]:
            if goodclaim(protocol,claimid):
                buf = DRAWGRAPH
                DRAWGRAPH = False
                res = TestClaim(protocol,claimid,self)
                DRAWGRAPH = buf
                if res == False:
                    return False
        return True

    def union(self,other):
        """
        Unions adversary rule set with that of other, yielding a
        possibly stronger adversary model.
        """
        for i in range(0,self.length):
            if self.vector[i] < other.vector[i]:
                self.vector[i] = other.vector[i]

    def getCorrectClaims(self):
        """
        Get the protocol claims correct for this model
        """
        global DB

        return DB[self.dbkey()]

    def getCorrectProtocols(self):
        """
        Get the protocols of which all claims are correct in this model
        """
        global DB
        global FCD

        ccl = self.getCorrectClaims()
        plseen = []
        for (prot,claim) in ccl:
            if prot not in plseen:
                plseen.append(prot)

        pl = []
        for prot in plseen:
            if self.isProtocolCorrect(prot):
                pl.append(prot)

        return pl

    def applyDelta(self,delta):
        """
        Apply delta to model
        """
        res = delta.getDelta()
        for i in range(0,self.length):
            if self.vector[i] < res[i]:
                self.vector[i] = res[i]


def FindClaims(filelist):
    """
    Get the claim ids

    returns a dict of filename to claimname*
    """
    ll = Scyther.GetClaims(filelist)
    llnew = {}
    for fn in ll.keys():
        if goodprotocol(fn):
            llnew[fn] = ll[fn]
    return llnew


class Traverse(object):
    """
    Iterator for adversary models.

    Designed to be optimal for filling the data, so it's a bit like a
    generalized binary search, but we do the min/max models at the start. Yeah,
    weird.
    """

    def __init__(self,unrestricted=False):

        self.step = -1
        if unrestricted:
            global SECMODELFULL

            self.full = True
            if SECMODELFULL == None:
                SECMODELFULL = self.constructList(unrestricted=True)
            self.size = len(SECMODELFULL)
        else:
            global SECMODELTRAVERSE

            self.full = False
            if SECMODELTRAVERSE == None:
                SECMODELTRAVERSE = self.constructList()
            self.size = len(SECMODELTRAVERSE)

    def __iter__(self):
        return self

    def next(self):
        global SECMODELFULL
        global SECMODELTRAVERSE

        self.step = self.step + 1
        if self.step >= self.size:
            raise StopIteration
        if self.full:
            return SECMODELFULL[self.step]
        else:
            return SECMODELTRAVERSE[self.step]

    def constructList(self,unrestricted=False):
        """
        Construct an optimal traversal list or a full list.

        It's essentially something like a binary search on a partially ordered
        structure, aiming to get rid of as many alternatives as possible early.

        Two phases:
        1. Construct a list of (model,min) pairs to indicate the ordering.
        2. Return the reverse sorted model list according to min.
        """
        # Phase 1
        mlist = []
        model = SecModel()
        maxer = model.countTypes()

        priority = []
        priority.append(SecModel())
        maxmodel = SecModel("max")

        while model != None:
            lower = len(model.getLowers())
            higher = len(model.getHighers())
            if lower < higher:
                min = lower
                max = higher
            else:
                min = higher
                max = lower
            val = (maxer * min) + max
            mlist.append((model.copy(),val))

            if model == maxmodel:
                priority.append(maxmodel)

            model = model.next(unrestricted=unrestricted)

        # Phase 2
        def msort( (s1,m1), (s2,m2) ):
            if s1 in priority:
                if s2 in priority:
                    # Compare positions
                    # If s1's index is lower, then negative, so s1 goes first
                    return priority.index(s1) - priority.index(s2)
                else:
                    # s1 is priority, other is not, so s1 goes first
                    return -1
            return m2-m1

        mlist.sort(cmp=msort)
        nlist = []
        #print
        #print "-" * 60
        for (s,m) in mlist:
            #print m,s
            nlist.append(s)
        #print "-" * 60
        #print
        return nlist


class NextOptimalOpen(object):
    """
    Iterator over protocol models for which no results are in the cache.

    Tries to be as good as possible in the worst case.
    """
    def __init__(self,fileid,claimid):
	self.fileid = fileid
	self.claimid = claimid
	self.toverify = None
	self.last = None

    def __iter__(self):
        return self

    def isOpen(self,model):
	global CACHE

	res = CACHE.get(self.fileid, self.claimid, model.dbkey())
	return (res == None)

    def next(self):
	"""
	We scan all open goals and choose the optimal one.

	We use a lexicographical ordering on the worst,best cases.
	"""

	max = SecModel().countTypes()
	bestgain = -1
	bestmodel = None
	remaining = 0
	for model in Traverse():
	    if self.isOpen(model):
		# Possible candidate
		remaining += 1
		lowers = 1
		highers = 1
		for model2 in Traverse():
		    if self.isOpen(model2):
			if model2.weakerthan(model):
			    lowers += 1
			if model.weakerthan(model2):
			    highers += 1
		if lowers > highers:
		    bestcase = lowers
		    worstcase = highers
		else:
		    bestcase = highers
		    worstcase = lowers
		gain = (max * worstcase) + bestcase
		if gain > bestgain:
		    bestgain = gain
		    bestmodel = model
	if bestmodel == None:
	    raise StopIteration
	else:
	    if bestmodel == self.last:
		global CACHE

		print CACHE.get(self.fileid, self.claimid, self.last.dbkey())
		raise "Trying to visit a model twice in a row, may lead to infinite loop. Aborting preemptively."
	    self.last = bestmodel
	    return (bestmodel,max - remaining)


class SecDelta(object):

    def __init__(self,model1,model2):

        # Need real copies
        self.model1 = model1.copy()
        self.model2 = model2.copy()

    def __str__(self):
        rl = []
        for i in range(0,self.model1.length):
            t1 = self.model1.describe(i)
            t2 = self.model2.describe(i)
            if t1 != t2:
                if t1 != "":
                    t1 = "-%s" % (t1)
                if t2 != "":
                    t2 = "+%s" % (t2)
                rl.append(t1 + t2)
        return ":".join(rl)

    def __cmp__(self,other):
        if (str(self) == str(other)):
            return 0
        else:
            return 1


    def dbkey(self):
        return str(self)

    def getDelta(self):
        res = []
        for i in range(0,self.model1.length):
            v1 = self.model1.vector[i]
            v2 = self.model2.vector[i]
            if v1 == v2:
                res.append(0)
            else:
                res.append(v2)
        return res


def VerifyClaim(file,claimid,model,onlycache=False):
    """
    Check claim in model
    """
    global DRAWGRAPH
    global DEFAULTARGS
    global CACHE
    global CALLSCYTHER

    claimres = CACHE.get(file,claimid,model.dbkey())
    if claimres != None:
        # Already in cache, return.
        return claimres

    """
    Below we actually verify it
    """
    if onlycache:
        return None

    DRAWGRAPH = False

    if CALLSCYTHER:
        """
        Normal proceedings: call Scyther to verify claim.
        """
        s = Scyther.Scyther()
        s.addFile(file)
        s.options = "%s %s" % (DEFAULTARGS,model.options())
        res = s.verifyOne(claimid)
        claimres = res[0].getRank()

        CACHE.setTransitive(file,claimid,model.dbkey(),claimres)

        return claimres
    else:
        """
        At exit code, we just assume it's sort of okay (2)
        """
        return 2


def TestClaim(file,claimid,model):
    claimres = VerifyClaim(file,claimid,model)
    if claimres < 2:
        return False
    else:
        return True


def Abbreviate(text,sep):
    """
    Abbreviate
    """
    i = text.rfind(sep)
    if i == -1:
        return text
    else:
        return text[i+1:]

def ShortClaim(claim):
    return Abbreviate(claim,",")

def ShortName(protname):
    return Abbreviate(protname,"/")

def Compress(datalist):
    """
    Compress datalist in string
    """
    mapping = {}
    # Extract claims to mapping
    for data in datalist:
        (prot,claim) = data
        shortclaim = ShortClaim(claim)
        try:
            mapping[prot] = mapping[prot] + [shortclaim]
        except KeyError:
            mapping[prot] = [shortclaim]
    # Summarize claims per protocol
    pl = []
    for prot in mapping.keys():
        global SHOWPATH

        if SHOWPATH:
            misc = " (%s)" % (prot)
        else:
            misc = ""
        shortprot = ShortName(prot)
        txt = "%s: %s%s" % (shortprot,"; ".join(mapping[prot]),misc)
        pl.append(txt)

    # After compression, we may have duplicate names.
    pl2 = pl
    pl = []
    for n in pl2:
        if n not in pl:
            pl.append(n)

    # Sort
    pl.sort()

    return pl


def getProtocolList():
    global FCD

    return FCD.keys()

def reportContext():
    """
    Report which protocols are broken by what
    """
    global SUMMARYDB

    print "Protocol nice breakage summary"
    print
    for prot in SUMMARYDB.keys():
        print prot
        for delta in SUMMARYDB[prot]:

            """
            Check if this delta *always* breaks the protocol
            """
            seen = []
            always = True
            for model in Traverse():
                model2 = model.copy()
                model2.applyDelta(delta)
                if model2 not in seen:
                    seen.append(model2)
                    if model2.isProtocolCorrect(prot):
                        always = False
                        break

            """
            Report
            """
            text = "\t%s" % (delta)
            if always == True:
                text = "%s (from any model)" % (text)
            print text


def addup(db,key,val):
    if db[key] < val:
        db[key] = val


def getMaxModels(mylist=None,direction=1):
    global RESTRICTEDMODELS

    if mylist == None:
        mylist = RESTRICTEDMODELS
    if mylist == None:
        return [SecModel(True)]
    else:
        mm = []
        for model in mylist:
            strongest = True
            for model2 in mylist:
                if model != model2:
                    if direction >= 0:
                        a = model
                        b = model2
                    else:
                        a = model2
                        b = model
                    if a.weakerthan(b):
                        strongest = False
                        break
            if strongest:
                mm.append(model)
        return mm

def drawbox(title="", prefix="",spacer=1):
    """
    Draw an ascii box
    """
    ttl = title.splitlines()
    max = 1
    for l in ttl:
        if len(l) > max:
            max = len(l)
    max = max + 2*spacer
    print prefix + "o" + "-" * (max) + "o"
    for l in ttl:
        inner = l.center(max)
        print prefix + "|%s|" % (inner)
    print prefix + "o" + "-" * (max) + "o"


def GraphCombinedHierarchy(force=False):
    """
    DB is a dict:
    model -> list of protocols

    a model is a list of parameters
    """
    global FCDN,FCDX,FCDS
    global DRAWGRAPH
    global FAST
    global ALLCORRECT
    global BRIEF
    global SUMMARYDB
    global ACLMAX
    global SCANERRORS
    global RESTRICTEDMODELS
    global GRAPHCH
    global FILTER

    if force == False:
        # Check for conditions not to draw
        if FAST == True:
            return
        if DRAWGRAPH == False:
            return

    if RESTRICTEDMODELS == None:
        print "x Not drawing combined hierarchy for all models (would be unreadable)."
        return

    print "- Writing combined hierarchy with full claim details."
    fp = open("%s.dot" % (GRAPHCH), "w")

    fp.write("digraph combinedHierarchyWithClaimDetails {\n")
    fp.write("\trankdir=BT;\n")

    modelsdone = 0
    modelscount = 0
    minmodel = SecModel(False)
    maxmodel = SecModel(True)

    """
    Init status thing
    """
    status = {}
    for model in Traverse():
        status[model.dbkey()] = 0
    status[minmodel.dbkey()] = 2
    status[maxmodel.dbkey()] = 2

    for model in Traverse():

        modelscount += 1
        """
        We get the list of follow-ups
        """
        nfrom = model.dotkey()
        correct = model.getCorrectClaims()

        highers = model.getHighers()
        if highers == []:
            """
            No highers. I guess we should draw the thing then.
            """
            addup(status,model.dbkey(),2)

        for (model2,description) in highers:
            """
            Each stronger model might involve drawing a counterexample
            arrow: i.e. a claim correct in model, but not in model2
            """
            nto = model2.dotkey()
            correct2 = model2.getCorrectClaims()

            cex = []
            skipped = []
            for x in correct:
                if x not in correct2:
                    if ALLCORRECT == True:
                        (prot,claimid) = x
                        shouldadd = model.isProtocolCorrect(prot)
                    else:
                        shouldadd = True

                    if shouldadd:
                        cex.append(x)
                    else:
                        skipped.append(x)

            # Decide wether to draw counterexamples
            if (cex == [] and skipped == []):
                drawcex = False
            else:
                drawcex = True

            # Override: sublist means no counterexamples
            if RESTRICTEDMODELS != None:
                drawcex = False

            if drawcex == False:
                """
                No counterexamples!
                """
                if BRIEF == False:
                    misc = "[label=\"%s: ???\",fontcolor=red,color=gray]" % (description)
                else:
                    misc = ""
                fp.write("\t%s -> %s %s;\n" % (nfrom,nto,misc))
                if SCANERRORS == True:
                    addup(status,model.dbkey(),2)
                    addup(status,model2.dbkey(),2)
                else:
                    addup(status,model.dbkey(),1)
                    addup(status,model2.dbkey(),1)

            else:
                """
                Counterexamples need a box
                """
                if SCANERRORS == False:
                    nmid = "mid_%s_%s" % (nfrom,nto)
                    if cex != []:
                        misc = "[shape=box,label=\"%s counterexamples:\\n%s\\l\"]" % (description,"\\l".join(Compress(cex)))
                    else:
                        if BRIEF == False:
                            misc = "[shape=box,color=white,fontcolor=gray,label=\"bad %s counterexamples:\\n%s\\l\"]" % (description,"\\l".join(Compress(skipped)))
                        else:
                            misc = "[label=\"bad counterexamples\\n exist\"]"

                    fp.write("\t%s %s;\n" % (nmid,misc))
                    fp.write("\t%s -> %s;\n" % (nfrom,nmid))
                    fp.write("\t%s -> %s;\n" % (nmid,nto))

                    addup(status,model.dbkey(),2)
                    #addup(status,model2.dbkey(),2)

    """
    Draw the nodes 
    """
    for model in Traverse():
        
        draw = status[model.dbkey()]
        if RESTRICTEDMODELS != None:
            if draw == 1:
                draw = 2

        if draw == 2:
    
            if FILTER != None:
                # We were filtering stuff
                acl = []
                for prot in model.getCorrectProtocols():
                    if model.isProtocolCorrect(prot):
                        highers = model.getHighers()
                        allafter = True
                        for (model2,descr) in highers:
                            if not model2.isProtocolCorrect(prot):
                                allafter = False
                                # Store in summary DB
                                try:
                                    SUMMARYDB[prot].append(descr)
                                except KeyError:
                                    SUMMARYDB[prot] = []
                        if (highers == []) or (not allafter) or (RESTRICTEDMODELS != None):
                            # Add to displayed list
                            nn = ShortName(prot)
                            if nn not in acl:
                                acl.append(nn)
                                if RESTRICTEDMODELS == None:
                                    if len(acl) == ACLMAX:
                                        break

                acl.sort()
                if RESTRICTEDMODELS == None:
                    if len(acl) == ACLMAX:
                        acl.append("...")
                misc = "\\n%s\\n" % ("\\n".join(acl))
            else:
                misc = ""

            text = "%s [style=filled,color=lightgray,label=\"Adversary model:\\n%s%s\"]" % (model.dotkey(),model.display(),misc)
            fp.write("\t%s;\n" % text)
        elif draw == 1:
            text = "%s [shape=point,label=\"\"]" % (model.dotkey())
            fp.write("\t%s;\n" % text)

    """
    Finish up by showing the final stuff
    """
    ml = getMaxModels()
    for model in ml:
        correct = model.getCorrectClaims()
        if len(correct) == 0:
            misc = "[shape=box,label=\"No claims found that\\lare correct in this model.\\l\"]"
        else:
            misc = "[shape=box,label=\"Correct in all:\\n%s\\l\"]" % ("\\l".join(Compress(correct)))
        fp.write("\t%s -> final_%s;\n" % (model.dotkey(),model.dotkey()))
        fp.write("\tfinal_%s %s;\n" % (model.dotkey(),misc))

    text = "Scanned %i/%i claims, %i skipped. Adversary models found: %i/%i." % (FCDX,FCDN,FCDS,modelsdone,modelscount)
    fp.write("\tlabel=\"%s\";\n" % text)
    fp.write("}\n")

    fp.flush()
    fp.close()
    commands.getoutput("dot -Tpdf %s.dot >%s.pdf" % (GRAPHCH, GRAPHCH))

    print "* Generated combined hierarchy graph."
    drawbox("%s.pdf" % (GRAPHCH), prefix="  ")
    print


class ProtCache(object):
    """
    Cache for a protocol

    contains claim x model -> res
    """
    def __init__(self,protocol):
        self.data = {}
        self.protocol = protocol

    def getClaims(self):
        claims = set()
        for (claim,model) in self.data.keys():
            claims.add(claim)
        return claims

    def getModels(self):
        models = set()
        for (claim,model) in self.data.keys():
            models.add(model)
        return models

    def set(self,claim,model,res):
        self.data[(claim,model)] = res

    def get(self,claim,dbkey,gethigher=True,getlower=True):
        """
        Here we don't exploit the hierarchy.
        """

        # First scan actual claim
        return self.data.get((claim,dbkey),None)

    def __str__(self):
        tl = []
        for (claim,model) in self.data.keys():
            tl.append("claim: %s, model %s, res: %s" % (claim,model,self.get(claim,model)))
        return "\n".join(tl)


def sortBuffer():
    """
    Sort the Cache file
    """
    global CACHEFILE

    ll = []
    try:
        fp = open(CACHEFILE,"r")
        for l in fp.xreadlines():
            ll.append(l)
        fp.close()
        ll.sort()
    except:
        print "Initializing cache file."

    fp = open(CACHEFILE,"w")
    for l in ll:
        fp.write(l)
    fp.close()
    

class ScytherCache(object):
    """
    Big buffer

    self.data = (protocol [file]) -> ((claim,model) -> res)
    """
    global CACHEFILE

    def __init__(self):
        self.data = {}
        try:
            fp = open(CACHEFILE,"r")
            print "Reloading cache file."
            for l in fp.xreadlines():
                da = (l.rstrip("\n")).split("\t")
                protocol = da[0]
                claim = da[1]
                dbkey = da[2]
                res = int(da[3])
                self.setForce(protocol,claim,dbkey,res)
            fp.close()

        except:
            pass


    def closeTransitive(self):
        """
        Compute the closure of the cache.
        """
        print "Computing transitive closure of verification cache."
        togo = 0
        for protocol in self.data.keys():
            togo += len(self.data[protocol].getClaims())

        if togo > 0:
            widgets = ['  Generating: ', Percentage(), ' ',
                       Bar(marker='#',left='[',right=']')
                       ]
            pbar = ProgressBar(widgets=widgets, maxval=togo)
            pbar.start()
            count = 0
            for protocol in self.data.keys():
                for claim in self.data[protocol].getClaims():
                    for dbkey in self.data[protocol].getModels():
                        # dbkey represents model
                        res = self.get(protocol,claim,dbkey)
                        if res != None:
                            self.setTransitive(protocol,claim,dbkey,res)
                    count += 1
                    pbar.update(count)
            pbar.finish()

        print "Closure computation completed."


    def setForce(self,protocol,claim,dbkey,res):
        """
        Store this item in the DB from cache
        """
        self.data.setdefault(protocol,ProtCache(protocol))
        self.data[protocol].set(claim,dbkey,res)

    def set(self,protocol,claim,dbkey,res):
        """
        Store this item in the DB.

        If it was not there yet, then also set it in the cache file.
        """
        if self.get(protocol,claim,dbkey) == None:
            """
            We don't overwrite old contents.
            """
            # Store in cache object
            self.setForce(protocol,claim,dbkey,res)

            # Write to cache
            fp = open(CACHEFILE,"a")
            fp.write("%s\t%s\t%s\t%s\n" % (protocol,claim,dbkey,res))
            fp.flush()
            fp.close()

    def setTransitive(self,file,claim,dbkey,res):
        """
        Similar arguments as set but better names, as the model
        really here is the dbkey.
        """
        # convert dbkey back to model
        model = SecModel()
        model.enscribe(dbkey)

	# Store self
        self.set(file,claim,dbkey,res)

        # For transitive closure we consider all models,
        # so we actually store the implications for use in
        # later (bigger) scans.
        for model2 in Traverse(unrestricted = True):
            oldres = self.get(file,claim,model2.dbkey())
            if oldres == None:
                # Not set yet, so something to store here
                if model != model2:
		    storehere = False
                    if res < 2:
                        # False in model, so also false in all stronger
                        if model.weakerthan(model2):
                            storehere = True
                    else:
                        # (semi)correct in model, so also correct in all weaker
                        if model2.weakerthan(model):
                            storehere = True
		    if storehere:
			self.set(file,claim,model2.dbkey(),res)

    def get(self,protocol,claim,dbkey):
        try:
            return self.data[protocol].get(claim,dbkey)
        except KeyError:
            return None

    def countProtocols(self):
        return len(self.data.keys())


def countOpen(file,claimid):
    """
    Count in how many models the claim is still undecided.
    """
    global CACHE

    open = 0
    for model in Traverse():
        if CACHE.get(file,claimid,model.dbkey()) == None:
            open += 1
    return open


def Investigate(file,claimid,callback=None):
    """
    Investigate this claim for all models.

    Currently always returns True. It used to return False if the claim was
    incorrect in all models.

    For multi-processing we may return the correct models in the queue, e.g.
    results.
      file
      claimid
      correctmodels

    Then the processing thread can append (file,claimid) to DB[model.dbkey()].
    Further (shared) storage is done by TestClaim


    """
    global DB

    data = (file,claimid)
    # Here we actually want an optimal scan (and not some linear thing)
    # so Traverse() is not so good here.
    for (model,done) in NextOptimalOpen(file,claimid):
        if callback != None:
            callback(done)
        res = TestClaim(file,claimid,model)
        if res:
            DB[model.dbkey()] = DB[model.dbkey()] + [data]

    return True

def goodprotocol(fname):
    """
    Filter out stuff
    """
    global BRIEF
    global FILTER

    # If we have a filter, use it
    if FILTER != None:
        BRIEF = True
        for subs in FILTER:
            if fname.find(subs) != -1:
                return True
        return False

    # Not bad, no filter: accept
    return True

def goodclaim(fname,cid):
    """
    Filter out stuff
    """
    global BRIEF

    if goodprotocol(fname) == False:
        return False

    # Not bad, no filter: accept
    return True


def subset(s1,s2):
    for x in s1:
        if x not in s2:
            return False
    return True

def strictsubset(s1,s2):
    if subset(s1,s2) and not subset(s2,s1):
        return True
    return False

def allTrueModels(fn,fix=False):
    """
    Return a set all models in which all claims of fn are true
    """
    global FCD

    allcorrect = set()
    for model in Traverse():

        yeahright = True
        for cid in FCD[fn]:
            if goodclaim(fn,cid):
                res = TestClaim(fn,cid,model)
                if res == False:
                    yeahright = False
                    break

        if yeahright == True:
            if fix:
                allcorrect.add(str(model))
            else:
                allcorrect.add(model.copy())

    return allcorrect


def filterImpliedModels(models):
    """
    Remove any implied models from the list.
    """
    nl = set()
    for model in models:
        remove = False
        for model2 in models:
            if model2 != model:
                if model.weakerthan(model2):
                    remove = True
                    break
        if not remove:
            nl.add(model)
    return nl


def pickfirst(dic,fn):
    """
    Pick a representative
    """
    for x in dic.keys():
        if fn in dic[x]:
            return x
    return fn


def dotabbrev(fn):
    """
    Shorten a filename for dot usage
    """
    global DOTABBREVS

    try:
        return DOTABBREVS[fn]
    except KeyError:
        pass

    # shorten
    repl = fn.replace("-","_")
    fullfile = repl.split("/")[-1]
    short = "P_%s" % fullfile.split(".")[0]
    while short in DOTABBREVS.values():
        short = short + "'"

    DOTABBREVS[fn] = short
    return short


def GetWeakersEquals(prots):
    """
    For all protocols infer weakers.

    Returns (wkrs,equals,AT), tuple of dicts. Each maps protocols to sets of protocols.
    """
    alltrue = {}
    AT = {}
    for fn in prots:
        # Store (caching for later)
        AT[fn] = allTrueModels(fn)
        # Fix contents to make set comparisons work
        alltrue[fn] = allTrueModels(fn,fix=True)

    wkrs = {}
    equals = {}
    for fn in prots:
        wkrs[fn] = set()
        equals[fn] = set()
        for fn2 in prots:
            if alltrue[fn] == alltrue[fn2]:
                equals[fn].add(fn2)
            else:
                if alltrue[fn].issuperset(alltrue[fn2]):
                    wkrs[fn].add(fn2)
    return (wkrs,equals,AT)
        

def GraphProtocolSecurityHierarchy():
    """
    Report the protocol-security hierarchy
    """
    global FCD
    global GRAPHPSH
    global FILTER
    global RESTRICTEDMODELS

    print "- Generating protocol-security hierarchy."
    fp = open("%s.dot" % (GRAPHPSH),"w")
    fp.write("digraph protocolSecurityHierarchy {\n")
    fp.write("\trankdir=BT;\n")

    # Progress bar
    maxcount = len(FCD.keys()) * 2
    widgets = ['  Generating: ', Percentage(), ' ',
               Bar(marker='#',left='[',right=']')
               ]
    pbar = ProgressBar(widgets=widgets, maxval=maxcount)
    pbar.start()
    count = 0

    # Infer dependencies
    (wkrs,equals,AT) = GetWeakersEquals(FCD.keys())

    # Report only minimal paths
    edges = set()
    for fn in FCD.keys():
        for pn in wkrs[fn]:
            # Report this link iff there is no node in between
            nope = True
            for xn in wkrs[fn]:
                if pn in wkrs[xn]:
                    nope = False
                    break
            if nope == True:
                edge = "\t%s -> %s;\n" % (dotabbrev(pickfirst(equals,pn)),dotabbrev(pickfirst(equals,fn)))
                if edge not in edges:
                    edges.add(edge)
                    fp.write(edge)
        count += 1
        pbar.update(count)

    # Name the nodes
    shownmodels = set()
    shown = set()
    for fn in FCD.keys():
        if not fn in shown:
            # Only draw equivalence class for fn once
            shown = shown.union(equals[fn])

            repr = pickfirst(equals,fn)
            if debugging():
                print
                print "Equiv. class, picked",
                print str(repr),
                print " from ",
                for x in equals[repr]:
                    print "<<%s>> " % (str(x)),
                print

            # Make the node name (line 2)
            nl = []
            for x in equals[repr]:
                da = dotabbrev(x)
                if da not in nl:
                    nl.append(da)

            nl.sort()
            txt = ",".join(nl)
            txt += "\\n"

            # Store whatever is already implied
            shownmodels = shownmodels.union(AT[repr])
            # Make the node models list
            # We want alltruemodels, except for:
            # - Anything implied among them
            # - Anything satisfied by weakers
            # Computed satisfied by weakers
            weakerssat = set()
            for fnw in wkrs[repr]:
                for mw in AT[fnw]:
                    weakerssat.add(str(mw))
            # Turn whatever is not satisfied into newmodels
            newmodels = set()
            for m in filterImpliedModels(AT[repr]):
                if str(m) not in weakerssat:
                    newmodels.add(m)
            # Combine names
            nm = []
            allshort = True
            for m in newmodels:
                 (short,xn) = m.shortornot()
                 if not short:
                     allshort = False
                 nm.append(xn)
            nm.sort()
            # Decide on how to layout
            if not allshort:
                sep = "\\n"
            else:
                sep = " ; "
            txt += sep.join(nm)

            # Output the dot code
            fp.write("\t%s [label=\"%s\"];\n" % (dotabbrev(repr),txt))

        count += 1
        pbar.update(count)

    # Draw the adversary models which have no satisfying protocols.
    notimplied = set()
    for model in Traverse():
        if model not in shownmodels:
            thisimplied = False
            for model2 in shownmodels:
                if model != model2:
                    if model.weakerthan(model2):
                        thisimplied = True
                        break
            if not thisimplied:
                notimplied.add(model)

    # Filter out any stronger ones (the weakest ones suffice)
    needed = set()
    for model in notimplied:
        reallyneeded = True
        for model2 in notimplied:
            if model != model2:
                if model2.weakerthan(model):
                    reallyneeded = False
                    break
        if reallyneeded:
            needed.add(model)

    # Display
    if len(needed) > 0:
        # Display
        txt = "The following models (and any stronger\\nmodels) have no satisfying protocol:\\n"
        tl = []
        for m in needed:
            tl.append(m.display())
        tl.sort()
        txt += "\\n".join(tl)
    else:
        txt = "All models have a satisfying protocol."
    fp.write("\tNOPROTOCOLS [label=\"%s\",shape=\"box\"];\n" % (txt))


    fp.write("};\n")
    fp.close()

    pbar.finish()

    commands.getoutput("dot -Tpdf %s.dot >%s.pdf" % (GRAPHPSH, GRAPHPSH))
    print "* Generated protocol-security hierarchy."
    drawbox("%s.pdf" % (GRAPHPSH), prefix="  ")
    print


def reportProtocolTable():
    """
    Report the table of protocols.
    """
    global FCD
    global RESTRICTEDMODELS
    global FILTER

    # Must have small number of models
    if RESTRICTEDMODELS == None:
        return

    # Must have small number of protocols
    #if FILTER == None:
    #    return
    
    maxprotwidth = 1
    for fn in FCD.keys():
        da = len(dotabbrev(fn))
        if da > maxprotwidth:
            maxprotwidth = da

    # attack string
    attackstr =   "X"
    noattackstr = "."

    maxmodwidth = len(attackstr)
    for model in Traverse():
        mw = len(model.shortname())
        if mw > maxmodwidth:
            maxmodwidth = mw

    # Protocols on Y axis, models on X
    header = " ".ljust(maxprotwidth)
    for model in Traverse():
        header += "|%s" % model.shortname().ljust(maxmodwidth)

    print header
    print "-" * len(header)

    def dasort(a,b):
        # Sort on dot abbreviation
        return fsort(dotabbrev,a,b)

    kal = []
    for fn in FCD.keys():
        kal.append(fn)
    kal.sort(dasort)

    for fn in kal:
        line = dotabbrev(fn).ljust(maxprotwidth)
        cntgood = 0
        cntbad = 0
        for model in Traverse():
            if model.isProtocolCorrect(fn) == False:
                res = attackstr
                cntbad += 1
            else:
                res = noattackstr
                cntgood += 1
            line += "|%s" % res.ljust(maxmodwidth)

        if (cntgood == 0) or (cntbad == 0):
            line += "\t[same for all models]"
        else:
            line += "\t[model matters]"
        print line

    print "-" * len(header)


def GraphModelHierarchy():
    """
    If a restricted set, write
    """
    global RESTRICTEDMODELS
    global GRAPHAMH

    if RESTRICTEDMODELS == None:
        print "x No model hierarchy generated because all models are considered."
        return

    print "- Generating model hierarchy"
    fp = open("%s.dot" % (GRAPHAMH),"w")
    fp.write("digraph {\n");
    fp.write("\trankdir=BT;\n")

    ml = RESTRICTEDMODELS
    for model in ml:
        txt = "\t%s [label=\"%s\"];\n" % (model.dotkey(),model.display())
        fp.write(txt)
        ml2 = model.getLowers();
        for (model2,desc) in ml2:
            txt = "\t%s -> %s;\n" % (model2.dotkey(),model.dotkey())
            fp.write(txt)

    fp.write("}\n");
    fp.close()
    commands.getoutput("dot -Tpdf %s.dot >%s.pdf" % (GRAPHAMH, GRAPHAMH))
    print "* Generated adversary model hierarchy."
    drawbox("%s.pdf" % (GRAPHAMH), prefix="  ")
    print


def exiter(graphs=[],modulo=None):
    global CALLSCYTHER
    global DRAWGRAPH
    global CACHEFILE
    global GRAPHPSH, GRAPHAMH, GRAPHCH

    CALLSCYTHER = False

    reportProtocolTable()

    print """

     .--==################################==--.
    |      Verification process completed      |
     `--==################################==--`
"""

    if modulo == None:
        print "- Sorting buffer at exit."
        sortBuffer()

    """
    Graphs
    """
    DRAWGRAPH = True
    if graphs == None:
        graphs = []
    if "mh" in graphs:
        GraphModelHierarchy()
    else:
        print "- No model hierarchy requested (--MH)"
    if "ch" in graphs:
        GraphCombinedHierarchy(True)
    else:
        print "- No combined hierarchy requested (--CH)"
    if "psh" in graphs:
        GraphProtocolSecurityHierarchy()
    else:
        print "- No protocol-security hierarchy requested (--PSH)"

    ### Report summary
    #reportContext()

    print """
The verification cache file has been updated, and a next run with the same
parameters will be fast. If you want to redo the analysis, just delete the
cache file (%s) and rerun the script.

Feel free to dig through the scripts, though be warned that they have been
written to just work, and not as high-maintenance code shared by several
individuals.
    """ % (CACHEFILE)


def main(protocollist = None, models = "CSF09", protocolpaths=["Protocols/AdversaryModels"],filefilter=None,graphs=[], debug=False, closecache=False, modulo=None):
    """
    Simple test case with a few protocols, or so it started out at least.
    """
    global DB
    global FCD,FCDN,FCDX,FCDS
    global DRAWGRAPH
    global CACHE
    global FILTER
    global DEBUG

    DEBUG = debug

    FILTER = protocollist
    if modulo == None:
        sortBuffer()

    import atexit

    atexit.register(exiter,graphs=graphs,modulo=modulo)

    InitRestricted(models)

    CACHE = ScytherCache()

    if closecache:
        CACHE.closeTransitive()
    
    list = []
    for path in protocolpaths:
        print path
        prots = Scyther.FindProtocols(path)
        for p in prots:
            if p not in list:
                list.append(p)

    if filefilter != None:
        nlist = []
        for protfile in list:
            if filefilter(protfile):
                nlist.append(protfile)
        list = nlist

    #print "Performing compromise analysis for the following protocols:", list
    #print

    FCD = FindClaims(list)
    FCDN = 0
    FCDX = 0
    for fn in FCD.keys():
        FCDN += len(FCD[fn])

    DB = {}
    for model in Traverse():
        DB[model.dbkey()] = []

    print "Considering %i models" % (len(DB.keys()))

    DRAWGRAPH = True
    counter = 0
    for fn in FCD.keys():
        counter += 1
        shortfn = ".".join(fn.split("/")[-1].split(".")[:-1])
        comment = "%i/%i: [%s] " % (counter,len(FCD.keys()), shortfn)
        """
        We make a progress bar for these.
        Counts: claims * models
        """
        maxclaims = len(FCD[fn])
        maxmodels = SecModel().countTypes()
        maxclmods = maxclaims * maxmodels

        # If needed, consider only modulo
        if modulo != None:
            modcount = 0
            (modulus,i) = eval(modulo)
        else:
            checkit = True

        if maxclmods > 0:
            incount = 0
            widgets = [comment, Percentage(), ' ',
                       Bar(marker='#',left='[',right=']')
                       ]
            pbar = ProgressBar(widgets=widgets, maxval=maxclmods)
            pbar.start()

            for cid in FCD[fn]:
                if goodclaim(fn,cid):

                    if modulo != None:
                        checkit = (modcount == i)
                        modcount = (modcount + 1) % modulus

                    if checkit:
                        DRAWGRAPH = Investigate(fn,cid,callback=(lambda x: pbar.update(incount + x)))
                    FCDX += 1
                else:
                    FCDS += 1
                incount += maxclaims

            pbar.finish()
        else:
            print comment + "Nothing to do."
        
    print
    print "Analysis complete."



# vim: set ts=4 sw=4 et list lcs=tab\:>-:
