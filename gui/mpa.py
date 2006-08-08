#!/usr/bin/python

"""

Test script to execute multi-protocol attacks on some test set.

"""

import Scyther

def MyScyther(protocollist,filter=None):
    """
    Evaluate the composition of the protocols in protocollist.
    If there is a filter, i.e. "ns3,I1" then only this specific claim
    will be evaluated.
    """
    s = Scyther.Scyther()
    s.options = "--match=2"
    if filter:
        s.options += " --filter=%s" % (filter)
    for protocol in protocollist:
        s.addFile(protocol)
    s.verify()
    return s
    
def getCorrectIsolatedClaims(protocolset):
    """
    Given a set of protocols, determine the correct claims when run in
    isolation.
    Returns a tuple, consisting of
    - a list of compiling protocols
    - a list of tuples (protocol,claimid) wich denote correct claims
    """
    correctclaims = []
    goodprotocols = []
    for protocol in protocolset:
        # verify protocol in isolation
        s = MyScyther([protocol])
        # investigate the results
        if not s.errors:
            goodprotocols.append(protocol)
            for claim in s.claims:
                if claim.okay:
                    correctclaims.append((protocol,claim.id))
    return (goodprotocols,correctclaims)

def findMPA(protocolset,protocol,claimid,maxcount=3):
    """
    The protocol claim is assumed to be correct. When does it break?
    """
    count = 2
    if len(protocolset) < maxcount:
        maxcount = len(protocolset)

    def verifyMPAlist(mpalist):
        # This should be a more restricted verification
        s = MyScyther(mpalist,claimid)
        cl = s.getClaim(claimid)
        if cl:
            if not cl.okay:
                # This is an MPA attack!
                print "I've found a multi-protocol attack on claim %s in the context %s." % (claimid,str(mpalist))
                return mpalist

    def constructMPAlist(mpalist,start,callback):
        if len(mpalist) < count:
            for pn in range(start,len(protocolset)):
                p = protocolset[pn]
                if p not in mpalist:
                    constructMPAlist(mpalist + [p],pn+1,callback)
        else:
            callback(mpalist)

    while count <= maxcount:
        constructMPAlist([protocol],0,verifyMPAlist)
        count += 1
    return None

def findAllMPA(protocolset,maxcount=3):
    """
    Given a set of protocols, find multi-protocol attacks
    """
    (protocolset,correct) = getCorrectIsolatedClaims(protocolset)
    print correct
    for (protocol,claimid) in correct:
        mpalist = findMPA(protocolset,protocol,claimid,maxcount=3)
        if mpalist:
            print "Darn, MPA on %s (%s) using %s" % (claimid,protocol,mpalist)

if __name__ == '__main__':
    list = ['me.spdl','ns3.spdl','nsl3.spdl']
    findAllMPA(list)




