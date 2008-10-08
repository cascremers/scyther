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

from Scyther import *

BOREDOM = None

def MyScyther(protocollist,filter=None):
    """
    Evaluate the composition of the protocols in protocollist.
    If there is a filter, i.e. "ns3,I1" then only this specific claim
    will be evaluated.
    """
    s = Scyther.Scyther()
    # untyped matching
    s.options = "--match=2"
    for protocol in protocollist:
        s.addFile(protocol)
    s.verifyOne(filter)
    return s
    

class SecModel(object):

    def __init__(self,minmax=None):

        axis1 = ["--LKRnotgroup=0","--LKRnotgroup=1"]
        axis2 = ["","--LKRactor=1"]
        axis3 = ["","--LKRaftercorrect=1","--LKRafter=1"]
        axis4 = ["","--SKR=1"]
        axis5 = ["","--SSRothers=1"]
        self.axes = [axis1,axis2,axis3,axis4,axis5]
        self.length = len(self.axes)

        if minmax == "max" or minmax == True:
            self.setMax()
        else:
            self.setMin()

    def setMin(self):
        self.vector = []
        for i in range(0,self.length):
            self.vector.append(0)

    def setMax(self):
        self.vector = []
        for i in range(0,self.length):
            self.vector.append(len(self.axes[i])-1)

    def describe(self,i):
        s = self.axes[i][self.vector[i]]
        if s.endswith("=1"):
            return s[2:-2]
        return ""

    def __str__(self,sep=" "):
        """
        Yield string
        """
        sl = []
        for i in range(0,self.length):
            x = self.describe(i)
            if len(x) > 0:
                sl.append(x)
        if sl == []:
            return "None"
        else:
            return sep.join(sl)

    def options(self):
        sl = []
        for i in range(0,self.length):
            sl.append(self.axes[i][self.vector[i]])
        return " ".join(sl)

    def dotkey(self):
        return self.__str__(sep="_")

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
            
            index = self.vector[i]
            if index == len(self.axes[i])-1:
                self.vector[i] = 0
            else:
                self.vector[i] = self.vector[i]+1
                return self
        return None

    def getDir(self,direction):
        """
        Return a list of tuples (model,descriptionstring)
        """
        
        others = []
        for i in range(0,self.length):

            index = self.vector[i]
            index2 = index + direction
            if (index2 >=0 ) and (index2 < len(self.axes[i])):
                model2 = self.copy()
                model2.vector[i] = index2
                txtold = self.describe(i)
                txtnew = model2.describe(i)
                if direction < 0:
                    swp = txtold
                    txtold = txtnew
                    txtnew = swp
                text = ""
                if txtold != "":
                    text += "-%s" % (txtold)
                if txtnew != "":
                    text += "+%s" % (txtnew)
                others.append((model2,text))
        return others

    def getLowers(self):
        return self.getDir(-1)

    def getHighers(self):
        return self.getDir(1)


def FindClaims(filelist):
    """
    Get the claim ids
    """
    return Scyther.GetClaims(filelist)


def TestClaim(file,claimid,model):
    """
    Check claim in model
    """
    s = Scyther.Scyther()
    s.addFile(file)
    s.options = model.options()
    res = s.verifyOne(claimid)
    claimres = res[0].getRank()
    if claimres < 2:
        return False
    else:
        return True

def GetIndex(list,el):
    for i in range(0,len(list)):
        if el == list[i]:
            return i
    return None

def GetDir(model,direction):
    
    models = GetModels()
    lowers = []
    for i in range(0,len(model)):

        index = GetIndex(models[i],model[i])
        index2 = index + direction
        if (index2 >= 0) and (index2 < len(self.axes[i])):
            model2 = self.copy()
            for j in range(0,len(model)):
                if j == i:
                    model2.append(models[i][index-1])
                else:
                    model2.append(model[j])
            lowers.append((model2,model.describe()))
    return lowers

def GetLowers(model):
    
    models = GetModels()
    lowers = []
    for i in range(0,len(model)):

        index = GetIndex(models[i],model[i])
        if index > 0:
            model2 = []
            for j in range(0,len(model)):
                if j == i:
                    model2.append(models[i][index-1])
                else:
                    model2.append(model[j])
            lowers.append((model2,model.describe()))
    return lowers


def GetHighers(model):
    
    models = GetModels()
    highers = []
    for i in range(0,len(model)):

        index = GetIndex(models[i],model[i])
        if index < (len(models[i])-1):
            model2 = []
            for j in range(0,len(model)):
                if j == i:
                    model2.append(models[i][index+1])
                else:
                    model2.append(model[j])
            highers.append((model2,model[i][2:-2]))
    return highers


def GetList(db,model):
    """
    Get the list of things on this node
    """
    highers = model.getHighers()
    mapping = {}
    # Extract claims to mapping
    for data in db[model.dbkey()]:
        inall = True
        for (model2,descr) in highers:
            if data not in db[model2.dbkey()]:
                inall = False
                break
        if (not inall) or (highers == []):
            (prot,claim) = data
            if prot in mapping.keys():
                mapping[prot] = mapping[prot] + [claim]
            else:
                mapping[prot] = [claim]
    # Summarize claims per protocol
    pl = []
    for prot in mapping.keys():
        txt = "%s: %s" % (prot,"; ".join(mapping[prot]))
        pl.append(txt)

    return pl


def DotGraph(db):
    """
    db is a dict:
    model -> list of protocols

    a model is a list of parameters
    """
    print "Writing graph"
    fname = "compromise-test"
    fp = open("%s.dot" % (fname), "w")

    fp.write("digraph Compromise {\n")

    model = SecModel()
    while model != None:

        pl = GetList(db,model)
        if pl == []:
            s = "[shape=point,label=\"%s\"]" % (str(model))
        else:
            label = "Correct in %s:\\n" % (str(model))
            s = "[shape=box,label=\"%s%s\"]" % (label,"\\n".join(pl))
        fp.write("\t%s %s;\n" % (model.dotkey(),s));
        lowers = model.getLowers()
        for (lower,change) in lowers:
            fp.write("\t%s -> %s [label=\"%s\"];\n" % (lower.dotkey(),model.dotkey(),change))
        model = model.next()

    fp.write("}\n")

    fp.flush()
    fp.close()

    commands.getoutput("dot -Tps %s.dot >%s.ps" % (fname,fname))


def boreID(file,claimid):
    return "%s*%s" % (file,claimid)

def isBoring(file,claimid):
    global BOREDOM

    if BOREDOM == None:
        BOREDOM = []
        try:
            fp = open("boring.txt","r")
            for l in fp.readlines():
                BOREDOM.append(l.rstrip("\n"))
            fp.close()
        except:
            pass

    return (boreID(file,claimid) in BOREDOM)


def addToBoring(file,claimid):

    fp = open("boring.txt","a")
    fp.write("%s\n" % boreID(file,claimid))
    fp.flush()
    fp.close()


def Investigate(db,file,claimid):
    """
    Investigate this one.
    """

    if not isBoring(file,claimid):

        minres = TestClaim(file,claimid,SecModel())
        if minres == True:
            maxres = TestClaim(file,claimid,SecModel(True))
            if minres != maxres:
                print "*" * 70
                print file,claimid
                print minres, maxres
                print "*" * 70

                data = (file,claimid)

                model = SecModel()
                db[model.dbkey()] = db[model.dbkey()] + [data]
                model = model.next()
                while model != None:
                    res = TestClaim(file,claimid,model)
                    if res:
                        db[model.dbkey()] = db[model.dbkey()] + [data]
                    model = model.next()
                return (True,db)

        addToBoring(file,claimid)
        ast = ""
    else:
        ast = " (buffered)"

    print "Not very interesting%s:" % ast,file,claimid
    return (False,db)

def main():
    """
    Simple test case with a few protocols
    """

    list = Scyther.FindProtocols("..")
    print "Performing compromise analysis for the following protocols:", list
    print
    fcd = FindClaims(list)
    db = {}
    model = SecModel()
    while model != None:
        db[model.dbkey()] = []
        model = model.next()

    for fn in fcd.keys():
        for cid in fcd[fn]:
            (changed,db) = Investigate(db,fn,cid)
            if changed:
                DotGraph(db)
        
    print
    print "Analysis complete."


if __name__ == '__main__':
    main()


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
