#!/usr/bin/python
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

In this example, compromise attacks.

Author: Cas Cremers

"""

import commands
import sys

from Scyther import *

CACHEFILE = "verification-result-cache.tmp"   # Filename of cache
SHOWPATH = False    # Switch to true to show paths in the graph
#DEFAULTARGS = "--max-runs=7 --extravert"
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

CACHE = None
DB = {} # Model.dbkey -> (fname,claimid)*
FCD = {}
FCDN = 0
FCDX = 0
FCDS = 0
DRAWGRAPH = True
DOTABBREVS = {}

RESTRICTEDMODELS = None # No restricted model set

"""
Names of PDF output files
"""
GRAPHPSH = "protocol-security-hierarchy"
GRAPHAMH = "adversary-model-hierarchy"
GRAPHCH = "combined-hierarchy-claimdetails"

def InitRestricted():
    """
    If we want restricted models, do so here.
    """
    global RESTRICTEDMODELS

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
    RESTRICTEDMODELS = [external, internal, kci, wpfs, pfs, bpr2000, br9395, ck2001hmqv, ck2001, eck]   # As in paper

    #RESTRICTEDMODELS = None #   default

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


class SecModel(object):

    def __init__(self,minmax=None):

        axis0 = ["--LKRnotgroup=0","--LKRnotgroup=1"]
        axis1 = ["","--LKRactor=1"]
        axis2 = ["","--LKRrnsafe=1","--LKRaftercorrect=1","--LKRafter=1"]
        axis3 = ["","--SKR=1"]
        axis4 = ["","--SSRfilter=1","--SSR=1"]
        axis5 = ["","--RNR=1","--RNRinfer=1"]

        #axis1 = ["--LKRnotgroup=1"]

        self.axes = [axis0,axis1,axis2,axis3,axis4,axis5]
        self.length = len(self.axes)

        if minmax == "max" or minmax == True:
            self.setMax()
        else:
            self.setMin()

        self.name=None


    def setName(self,name):

        self.name = name


    def ax(self,ax):
        """
        Yield max+1 of the axis
        """
        return len(self.axes[ax])


    def countTypes(self):
        """
        Give the number of possible adversary types
        """
        count = 1
        for i in range(0,self.length):
            count = count * self.ax(i)
        return count

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

    def setMin(self):
        global RESTRICTEDMODELS

        if RESTRICTEDMODELS == None:
            self.vector = []
            for i in range(0,self.length):
                self.vector.append(0)
        else:
            RESTRICTEDMODELS[0].copy(tomodel=self)


    def setMax(self):
        global RESTRICTEDMODELS

        if RESTRICTEDMODELS == None:
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
        global RESTRICTEDMODELS

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

    def next(self):
        """
        Increase a given model, or return None when done
        """
        global RESTRICTEDMODELS

        if RESTRICTEDMODELS == None:
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
        Unions self with other
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


def VerifyClaim(file,claimid,model):
    """
    Check claim in model
    """
    global DRAWGRAPH
    global DEFAULTARGS
    global CACHE
    global CALLSCYTHER

    claimres = CACHE.get(file,claimid,model.dbkey())
    if claimres != None:
        return claimres

    DotGraph()
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

        CACHE.append(file,claimid,model.dbkey(),claimres)
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
        if prot in mapping.keys():
            mapping[prot] = mapping[prot] + [shortclaim]
        else:
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
            model = SecModel()
            always = True
            while model != None:
                model2 = model.copy()
                model2.applyDelta(delta)
                if model2 not in seen:
                    seen.append(model2)
                    if model2.isProtocolCorrect(prot):
                        always = False
                        break

                model = model.next()

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


def DotGraph(force=False):
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

    if force == False:
        # Check for conditions not to draw
        if FAST == True:
            return
        if DRAWGRAPH == False:
            return

    print "Writing combined hierarchy with full claim details."
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
    model = SecModel()
    while model != None:
        status[model.dbkey()] = 0
        model = model.next()
    status[minmodel.dbkey()] = 2
    status[maxmodel.dbkey()] = 2

    model = SecModel()
    while model != None:

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

        model = model.next()

    """
    Draw the nodes 
    """
    model = SecModel()
    while model != None:
        
        draw = status[model.dbkey()]
        if RESTRICTEDMODELS != None:
            if draw == 1:
                draw = 2

        if draw == 2:
    
            if len(sys.argv[1:]) > 0:
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
                                if prot not in SUMMARYDB.keys():
                                    SUMMARYDB[prot] = []
                                if descr not in SUMMARYDB[prot]:
                                    SUMMARYDB[prot].append(descr)
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

        model = model.next()

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
    print "Graph written"

    commands.getoutput("dot -Tpdf %s.dot >%s.pdf" % (GRAPHCH, GRAPHCH))

class ProtCache(object):
    """
    Cache for a protocol

    contains claim x model -> res
    """
    def __init__(self,protocol):
        self.data = {}
        self.protocol = protocol

    def getClaims(self):
        claims = []
        for (claim,model) in self.data.keys():
            claims.append(claim)
        return claims

    def set(self,claim,model,res):
        self.data[(claim,model)] = res

    def get(self,claim,dbkey,gethigher=True,getlower=True):
        """
        Here we exploit the hierarchy.
        """

        # First scan actual claim
        if (claim,dbkey) in self.data.keys():
            return self.data[(claim,dbkey)]

        # Generate model from dbkey for later use.
        model = SecModel()
        model.enscribe(dbkey)
        # The claim may be correct (at best)
        maxpos = 3
        maxexample = None
        # The claim may be wrong (at worst)
        minpos = 0
        minexample = None

        # Scan if any higher dbkey (i.e. stronger) already had a correct
        # (3 == verified) verdict: in that case the current model cannot
        # Scan stronger models. They can only introduce additional
        # attacks, but not more correctness. Hence they influence
        # minpos: if they don't contain an attack, there is none.
        if gethigher:
            cmodels = model.getHighers(all=True)
            for (model2,delta) in cmodels:
                res = self.get(claim,model2.dbkey(),getlower=False)
                if res != None:
                    if res > minpos:
                        minpos = res
                        minexample = model2

        # Scan if any lower dbkey (i.e. weaker) already had a false (0
        # == attack) verdict
        if getlower:
            cmodels = model.getLowers(all=True)
            for (model2,delta) in cmodels:
                res = self.get(claim,model2.dbkey(),gethigher=False)
                if res != None:
                    if res < maxpos:
                        maxpos = res
                        maxexample = model2

        # Now we squeeze
        if minpos == maxpos:
            return minpos

        # Sanity check
        if minpos > maxpos:
            print "Strange hierarchy inconsistency for claim %s" % claim
            print minexample
            print maxexample
            sys.exit()

        return None

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
    fp = open(CACHEFILE,"r")
    for l in fp.readlines():
        ll.append(l)
    fp.close()

    ll.sort()

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
            for l in fp.readlines():
                da = (l.rstrip("\n")).split("\t")
                protocol = da[0]
                claim = da[1]
                model = da[2]
                res = int(da[3])
                self.set(protocol,claim,model,res)
            fp.close()
        except:
            pass

    def set(self,protocol,claim,model,res):
        if protocol not in self.data.keys():
            self.data[protocol] = ProtCache(protocol)
        self.data[protocol].set(claim,model,res)

        #print "Stored %s : %s" % (protocol,self.data[protocol])

    def get(self,protocol,claim,model):
        if protocol in self.data.keys():
            return self.data[protocol].get(claim,model)
        else:
            return None

    def append(self,protocol,claim,model,res):
        if self.get(protocol,claim,model) == None:
            self.set(protocol,claim,model,res)
            fp = open(CACHEFILE,"a")
            fp.write("%s\t%s\t%s\t%s\n" % (protocol,claim,model,res))
            fp.flush()
            fp.close()

    def countProtocols(self):
        return len(self.data.keys())


def Investigate(file,claimid):
    """
    Investigate this one.
    """
    global DB

    minres = TestClaim(file,claimid,SecModel())
    if minres == True:
        #print "*" * 70
        #print file,claimid
        #print "*" * 70

        data = (file,claimid)

        model = SecModel()
        DB[model.dbkey()] = DB[model.dbkey()] + [data]
        model = model.next()
        while model != None:
            res = TestClaim(file,claimid,model)
            if res:
                DB[model.dbkey()] = DB[model.dbkey()] + [data]
            model = model.next()
        return True

    #print "Always flawed:",file,claimid
    return False

def goodprotocol(fname):
    """
    Filter out stuff
    """
    global BRIEF

    filefilter = ["../gui/Protocols/key-compromise/neumannstub-hwang.spdl", "../protocols/misc/compositionality-examples/","../protocols/misc/naxos-attempt3-quick.spdl","../protocols/misc/compromise/JFKr.spdl","email-","neumannstub"]
    for segment in filefilter:
        if fname.find(segment) != -1:
            return False

    # If we have a filter, use it
    protfilter = sys.argv[1:]
    if len(protfilter) > 0:
        BRIEF = True
        for subs in protfilter:
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

    # Get rid of bad
    filter = ["ksl,","ksl-Lowe,"]
    for pref in filter:
        if cid.startswith(pref):
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

def allTrueModels(fn):
    """
    Return all models in which all claims of fn are true
    """
    global FCD

    model = SecModel()
    allcorrect = []
    while model != None:

        yeahright = True
        for cid in FCD[fn]:
            if goodclaim(fn,cid):
                res = TestClaim(fn,cid,model)
                if res == False:
                    yeahright = False
                    break
        if yeahright == True:
            allcorrect.append(model)

        model = model.next()
    return allcorrect


def reportWeaker(fn):
    """
    Report all weaker protocols
    """
    global FCD

    at = allTrueModels(fn)
    weakers = []
    equals = []
    for fn2 in FCD.keys():
        if fn != fn2:
            at2 = allTrueModels(fn2)
            if subset(at2,at):
                if subset(at,at2):
                    equals.append(fn2)
                else:
                    weakers.append(fn2)
        else:
            equals.append(fn2)
    return (weakers,equals)


def pickfirst(dic,fn):
    """
    Pick a representative
    """
    for x in dic.keys():
        if x == fn:
            return x
        if fn in dic[x]:
            return x
    return fn


def dotabbrev(fn):
    """
    Shorten a filename for dot usage
    """
    global DOTABBREVS

    if fn in DOTABBREVS.keys():
        return DOTABBREVS[fn]

    # shorten
    repl = fn.replace("-","_")
    fullfile = repl.split("/")[-1]
    short = "P_%s" % fullfile.split(".")[0]
    while short in DOTABBREVS.values():
        short = short + "'"

    DOTABBREVS[fn] = short
    return short


def reportProtocolHierarchy():
    """
    Report the protocol-security hierarchy
    """
    global FCD
    global GRAPHPSH

    if len(sys.argv[1:]) == 0:
        return

    print "Writing protocol hierarchy."
    fp = open("%s.dot" % (GRAPHPSH),"w")
    fp.write("digraph protocolSecurityHierarchy {\n")
    fp.write("\trankdir=BT;\n")

    # Infer dependencies
    wkrs = {}
    equals = {}
    for fn in FCD.keys():
        (ll,eq) = reportWeaker(fn)
        wkrs[fn] = []
        equals[fn] = []
        for pn in ll:
            wkrs[fn].append(pn)
        for pn in eq:
            equals[fn].append(pn)

    # Report only minimal paths
    edges = []
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
                    edges.append(edge)
    for edge in edges:
        fp.write(edge)

    # Name the nodes
    shown = []
    for fn in FCD.keys():
        repr = pickfirst(equals,fn)
        if not repr in shown:
            shown.append(repr)
            nl = []
            for x in equals[repr]:
                da = dotabbrev(x)
                if da not in nl:
                    nl.append(da)

            nl.sort()
            txt = ",".join(nl)
            txt += "\\n"
            models = allTrueModels(fn)
            nm = []
            for m in models:
                nm.append(m.shortname())
            nm.sort()
            txt += " ; ".join(nm)
            fp.write("\t%s [label=\"%s\"];\n" % (dotabbrev(repr),txt))

    fp.write("};\n")
    fp.close()
    commands.getoutput("dot -Tpdf %s.dot >%s.pdf" % (GRAPHPSH, GRAPHPSH))
    print "Done."


def reportProtocolTable():
    """
    Report the table of protocols.
    """
    global FCD
    global RESTRICTEDMODELS

    # Must have small number of models
    if RESTRICTEDMODELS == None:
        return

    # Must have small number of protocols
    #if len(sys.argv[1:]) == 0:
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
    model = SecModel()
    while model != None:
        mw = len(model.shortname())
        if mw > maxmodwidth:
            maxmodwidth = mw
        model = model.next()

    # Protocols on Y axis, models on X
    header = " ".ljust(maxprotwidth)
    model = SecModel()
    while model != None:
        header += "|%s" % model.shortname().ljust(maxmodwidth)
        model = model.next()

    print header
    print "-" * len(header)

    def fsort(f,a,b):
        if f(a) > f(b):
            return 1
        elif f(a) < f(b):
            return -1
        else:
            return 0

    def dasort(a,b):
        # Sort on dot abbreviation
        return fsort(dotabbrev,a,b)

    kal = []
    for fn in FCD.keys():
        kal.append(fn)
    kal.sort(dasort)

    for fn in kal:
        line = dotabbrev(fn).ljust(maxprotwidth)
        model = SecModel()
        cntgood = 0
        cntbad = 0
        while model != None:
            if model.isProtocolCorrect(fn) == False:
                res = attackstr
                cntbad += 1
            else:
                res = noattackstr
                cntgood += 1
            line += "|%s" % res.ljust(maxmodwidth)
            model = model.next()
        if (cntgood == 0) or (cntbad == 0):
            line += "\t[same for all models]"
        else:
            line += "\t[model matters]"
        print line

    print "-" * len(header)


def WriteHierarchy():
    """
    If a restricted set, write
    """
    global RESTRICTEDMODELS
    global GRAPHAMH

    if RESTRICTEDMODELS == None:
        return

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

def exiter():
    global CALLSCYTHER
    global DRAWGRAPH
    global CACHEFILE
    global GRAPHPSH, GRAPHAMH, GRAPHCH

    CALLSCYTHER = False

    DRAWGRAPH = True
    DotGraph(True)

    ### Report summary
    #reportContext()

    reportProtocolHierarchy()
    reportProtocolTable()

    print "Sorting buffer at exit."
    sortBuffer()
    print """

     .--==################################==--.
    |      Verification process completed      |
     `--==################################==--`

The verification cache file has been updated, and a next run with the same
parameters will be fast. If you want to redo the analysis, clear the
verification file (%s), i.e., make it the empty file.

In the current directory you should now find three new PDF files generated
from the protocol analysis results:

1. '%s.pdf'

  The adversary-model hierarchy. This graph is reproduced as Figure 3 in the
  paper.

2. '%s.pdf'

  The protocol-security hierarchy. This graph is reproduced as Figure 4 in the
  paper.

3. '%s.pdf'

  A more detailed graph with specific claims. This is not so interesting for
  the setup in the paper,but is useful if you'd hack one of the scripts and
  make sure RESTRICTEDMODELS is always None, enforcing varification in all 112
  models.  Get a large coffee. Watch a movie.


Feel free to dig through the scripts, though be warned that they have been
written to just work, and not as high-maintenance code shared by several
individuals.
    """ % (CACHEFILE, GRAPHAMH, GRAPHPSH, GRAPHCH)

def main():
    """
    Simple test case with a few protocols
    """
    global DB
    global FCD,FCDN,FCDX,FCDS
    global DRAWGRAPH
    global CACHE

    sortBuffer()

    import atexit

    atexit.register(exiter)

    InitRestricted()

    CACHE = ScytherCache()
    
    WriteHierarchy()

    list = Scyther.FindProtocols("Protocols/AdversaryModels")
    #print "Performing compromise analysis for the following protocols:", list
    #print

    FCD = FindClaims(list)
    FCDN = 0
    FCDX = 0
    for fn in FCD.keys():
        FCDN += len(FCD[fn])

    DB = {}
    model = SecModel()
    while model != None:
        DB[model.dbkey()] = []
        model = model.next()
    print "Considering %i models" % (len(DB.keys()))

    DotGraph(True)
    DRAWGRAPH = True
    counter = 0
    for fn in FCD.keys():
        counter += 1
        print "Processing %i out of %i keys: %s" % (counter,len(FCD.keys()), fn)
        for cid in FCD[fn]:
            if goodclaim(fn,cid):
                DRAWGRAPH = Investigate(fn,cid)
                FCDX += 1
            else:
                FCDS += 1
        
    print
    print "Analysis complete."


if __name__ == '__main__':
    main()


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
