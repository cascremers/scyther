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

from Scyther import *

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
    

def GetModels():
    axis1 = ["--LKRnotgroup=0","--LKRnotgroup=1"]
    axis2 = ["","--LKRactor=1"]
    axis3 = ["","--LKRaftercorrect=1","--LKRafter=1"]
    axis4 = ["","--SKR=1"]
    axis5 = ["","--SSRothers=1"]
    return [axis1,axis2,axis3,axis4,axis5]


def GetMin():
    m = GetModels()
    l = []
    for x in m:
        l.append(x[0])
    return l

def GetMax():
    m = GetModels()
    l = []
    for x in m:
        l.append(x[-1])
    return l


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
    s.options = " ".join(model)
    res = s.verifyOne(claimid)
    claimres = res[0].getRank()
    return claimres


def Investigate(file,claimid):
    """
    Investigate this one.
    """
    minres = TestClaim(file,claimid,GetMin())
    maxres = TestClaim(file,claimid,GetMax())
    if minres != maxres:
        print "*" * 70
        print file,claimid
        print minres, maxres
        print "*" * 70
    else:
        print "Not very interesting:",file,claimid,minres

def main():
    """
    Simple test case with a few protocols
    """

    list = Scyther.FindProtocols("..")
    print "Performing compromise analysis for the following protocols:", list
    print
    fcd = FindClaims(list)
    for fn in fcd.keys():
        for cid in fcd[fn]:
            Investigate(fn,cid)
    print
    print "Analysis complete."


if __name__ == '__main__':
    main()


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
