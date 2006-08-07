#!/usr/bin/python

"""

Test script to execute multi-protocol attacks on some test set.

"""

import Scyther

def MyScyther(protocollist):
    s = Scyther.Scyther()
    s.options = "-m2"
    for protocol in protocollist:
        s.addFile(protocol)
    s.verify()
    return s
    
def getCorrectIsolatedClaims(protocolset):
    """
    Given a set of protocols, determine the correct claims when run in
    isolation.
    Returns a list of tuples (protocol,claimid)
    """
    correct = []
    for protocol in protocolset:
        # verify protocol in isolation
        s = MyScyther([protocol])
        # investigate the results
        for claim in s.claims:
            if claim.okay:
                correct.append((protocol,claim.id))
    return correct

def findMPA(protocolset,protocol,claimid,maxcount=3):
    """
    The protocol claim is assumed to be correct. When does it break?
    """
    count = 2

    def verifyMPAlist(mpalist):
        # This should be a more restricted verification
        print "verifying %s" % mpalist
        s = MyScyther(mpalist)
        cl = s.getClaim(claimid)
        if cl:
            if not cl.okay:
                # This is an MPA attack!
                print "Attack!"
                return mpalist
        return None

    def constructMPAlist(mpalist,callback):
        if len(mpalist) < count:
            for p in protocolset:
                if p not in mpalist:
                    return constructMPAlist(mpalist + [p],callback)
        else:
            return callback(mpalist)

    while count <= maxcount:
        mpalist = constructMPAlist([protocol],verifyMPAlist)
        if mpalist:
            return mpalist
        count += 1
    return None

def findAllMPA(protocolset,maxcount=3):
    """
    Given a set of protocols, find multi-protocol attacks
    """
    correct = getCorrectIsolatedClaims(protocolset)
    print correct
    for (protocol,claimid) in correct:
        mpalist = findMPA(protocolset,protocol,claimid,maxcount=3)
        if mpalist:
            print "Darn, MPA on %s (%s) using %s" % (claimid,protocol,mpalist)

if __name__ == '__main__':
    list = ['me.spdl','ns3.spdl','nsl3.spdl']
    findAllMPA(list)




