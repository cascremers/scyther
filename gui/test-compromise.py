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

SHOWPATH = False    # Switch to true to show paths in the graph
DEFAULTARGS = "--max-runs=7"
ALLCORRECT = True   # Require all claims to be correct of the protocol in prev. node for counterexample
BRIEF = False
FAST = True    # True means Skip intermediate graph drawing

SUMMARYDB = {}      # prot -> delta
SUMMARYALL = False  # Delta's in all or in some contexts?
ACLMAX = 10         # After 10 we give up for the nodes

CACHE = None
DB = {} # Model.dbkey -> (fname,claimid)*
FCD = {}
FCDN = 0
FCDX = 0
FCDS = 0
DRAWGRAPH = True


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

class SecModel(object):

    def __init__(self,minmax=None):

        axis0 = ["--LKRnotgroup=0","--LKRnotgroup=1"]
        axis1 = ["","--LKRactor=1"]
        axis2 = ["","--LKRrnsafe=1","--LKRaftercorrect=1","--LKRafter=1"]
        axis3 = ["","--SKR=1"]
        axis4 = ["","--SSR=1"]
        axis5 = ["","--RNR=1"]

        #axis1 = ["--LKRnotgroup=1"]

        self.axes = [axis0,axis1,axis2,axis3,axis4,axis5]
        self.length = len(self.axes)

        if minmax == "max" or minmax == True:
            self.setMax()
        else:
            self.setMin()

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

    def setMin(self):
        self.vector = []
        for i in range(0,self.length):
            self.vector.append(0)

    def checkSane(self,correct=False):
        """
        Makes a thing sane if correct==True

        We always assume 0 and max-1 are allowed for all vectors in all cases
        (empty model, max model)

        returns true if it was sane (and hence is surely unchanged)
        """
        sane = True
        for i in range(0,self.length):
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

    def setMax(self):
        self.vector = []
        for i in range(0,self.length):
            self.vector.append(self.ax(i)-1)
        self.checkSane(True)

    def describe(self,i):
        s = self.axes[i][self.vector[i]]
        if s.endswith("=1"):
            return s[2:-2]
        return ""

    def __str__(self,sep=" ",empty="External"):
        """
        Yield string
        """
        sl = []
        for i in range(0,self.length):
            x = self.describe(i)
            if len(x) > 0:
                sl.append(x)
        if sl == []:
            return empty
        else:
            return sep.join(sl)

    def options(self):
        sl = []
        for i in range(0,self.length):
            sl.append(self.axes[i][self.vector[i]])
        return " ".join(sl)

    def dotkey(self):
        return self.__str__(sep="_",empty="None")

    def dbkey(self):
        return self.dotkey()

    def __cmp__(self,other):
        if other != None:
            if self.vector == other.vector:
                return 0
        return 1

    def copy(self):
        """
        Make a copy
        """
        other = SecModel()
        other.vector = []
        for i in range(0,self.length):
            other.vector.append(self.vector[i])
        return other

    def next(self):
        """
        Increase a given model, or return None when done
        """
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

    def getDir(self,direction):
        """
        Return a list of tuples (model,deltadescr)
        """
        
        others = []
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

        return others

    def getLowers(self):
        return self.getDir(-1)

    def getHighers(self):
        return self.getDir(1)

    def isProtocolCorrect(self,protocol):
        """
        Is this protocol correct in this model?
        """
        global DRAWGRAPH
        global FCD

        for claimid in FCD[protocol]:
            buf = DRAWGRAPH
            DRAWGRAPH = False
            res = TestClaim(protocol,claimid,self)
            DRAWGRAPH = buf
            if res == False:
                return False
        return True


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
    return Scyther.GetClaims(filelist)


def VerifyClaim(file,claimid,model):
    """
    Check claim in model
    """
    global DRAWGRAPH
    global DEFAULTARGS
    global CACHE

    claimres = CACHE.get(file,claimid,model.dbkey())
    if claimres != None:
        return claimres

    DotGraph()
    DRAWGRAPH = False
    s = Scyther.Scyther()
    s.addFile(file)
    s.options = "%s %s" % (DEFAULTARGS,model.options())
    res = s.verifyOne(claimid)
    claimres = res[0].getRank()

    CACHE.append(file,claimid,model.dbkey(),claimres)
    return claimres

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

    if force == False:
        # Check for conditions not to draw
        if FAST == True:
            return
        if DRAWGRAPH == False:
            return

    print "Writing graph"
    fname = "compromise-test"
    fp = open("%s.dot" % (fname), "w")

    fp.write("digraph Compromise {\n")

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

        for (model2,description) in model.getHighers():
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

            if (cex == [] and skipped == []):
                """
                No counterexamples!
                """
                if BRIEF == False:
                    misc = "[label=\"%s: ???\",fontcolor=red,color=gray]" % (description)
                else:
                    misc = ""
                fp.write("\t%s -> %s %s;\n" % (nfrom,nto,misc))
                addup(status,model.dbkey(),1)
                addup(status,model2.dbkey(),1)

            else:
                """
                Counterexamples need a box
                """
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

        if status[model.dbkey()] == 2:
    
            if len(sys.argv[1:]) > 0:
                # We were filtering stuff
                acl = []
                for prot in model.getCorrectProtocols():
                    if model.isProtocolCorrect(prot):
                        allafter = True
                        for (model2,descr) in model.getHighers():
                            if not model2.isProtocolCorrect(prot):
                                allafter = False
                                # Store in summary DB
                                if prot not in SUMMARYDB.keys():
                                    SUMMARYDB[prot] = []
                                if descr not in SUMMARYDB[prot]:
                                    SUMMARYDB[prot].append(descr)
                        if not allafter:
                            # Add to displayed list
                            nn = ShortName(prot)
                            if nn not in acl:
                                acl.append(nn)
                                if len(acl) == ACLMAX:
                                    break

                acl.sort()
                if len(acl) == ACLMAX:
                    acl.append("...")
                misc = "\\n%s\\n" % ("\\n".join(acl))
            else:
                misc = ""

            text = "%s [style=filled,color=lightgray,label=\"Adversary model:\\n%s%s\"]" % (model.dotkey(),str(model),misc)
            fp.write("\t%s;\n" % text)
        elif status[model.dbkey()] == 1:
            text = "%s [shape=point,label=\"\"]" % (model.dotkey())
            fp.write("\t%s;\n" % text)

        model = model.next()

    """
    Finish up by showing the final stuff
    """
    model = SecModel(True)
    correct = model.getCorrectClaims()
    if len(correct) == 0:
        misc = "[shape=box,label=\"No claims found that\\lare correct in all models.\\l\"]"
    else:
        misc = "[shape=box,label=\"%s Correct in all:\\n%s\\l\"]" % (description,"\\l".join(Compress(correct)))
    fp.write("\t%s -> final;\n" % (model.dotkey()))
    fp.write("\tfinal %s;\n" % (misc))

    text = "Scanned %i/%i claims, %i skipped. Adversary models found: %i/%i." % (FCDX,FCDN,FCDS,modelsdone,modelscount)
    fp.write("\tlabel=\"%s\";\n" % text)
    fp.write("}\n")

    fp.flush()
    fp.close()
    print "Graph written"

    commands.getoutput("dot -Tpdf %s.dot >%s.pdf" % (fname,fname))

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

    def get(self,claim,model):
        if (claim,model) in self.data.keys():
            return self.data[(claim,model)]
        return None

    def __str__(self):
        tl = []
        for (claim,model) in self.data.keys():
            tl.append("claim: %s, model %s, res: %s" % (claim,model,self.get(claim,model)))
        return "\n".join(tl)

class ScytherCache(object):
    """
    Big buffer

    self.data = (protocol [file]) -> ((claim,model) -> res)
    """
    def __init__(self):
        self.data = {}
        try:
            fp = open("boring.data","r")
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
            fp = open("boring.data","a")
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

def goodclaim(fname,cid):
    """
    Filter out stuff
    """
    global BRIEF

    # First, get rid of bad
    filter = ["ksl,","ksl-Lowe,"]
    for pref in filter:
        if cid.startswith(pref):
            return False
    filefilter = ["../gui/Protocols/key-compromise/neumannstub-hwang.spdl", "../protocols/misc/compositionality-examples/","../protocols/misc/naxos-attempt3-quick.spdl"]
    for pref in filefilter:
        if fname.startswith(pref):
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

def main():
    """
    Simple test case with a few protocols
    """
    global DB
    global FCD,FCDN,FCDX,FCDS
    global DRAWGRAPH
    global CACHE

    CACHE = ScytherCache()
    
    list = Scyther.FindProtocols("..")
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
    for fn in FCD.keys():
        for cid in FCD[fn]:
            if goodclaim(fn,cid):
                DRAWGRAPH = Investigate(fn,cid)
                FCDX += 1
            else:
                FCDS += 1
        
    DRAWGRAPH = True
    DotGraph(True)
    reportContext()
    print
    print "Analysis complete."


if __name__ == '__main__':
    main()


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
