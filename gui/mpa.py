#!/usr/bin/python

"""

Example script to show how to perform large-scale tests using the
Scyther Python API (contained in the Scyther subdirectory)

In this example, multi-protocol attack analysis is performed on a small
test set.

Author: Cas Cremers

"""

from Scyther import Scyther

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
        goodprotocols.append(protocol)
        for claim in s.claims:
            if claim.okay:
                correctclaims.append((protocol,claim.id))
    return (goodprotocols,correctclaims)

def verifyMPAlist(mpalist,claimid):
    """
    Verify the existence of an attack in this context

    If an attack is found, we return False, otherwise True. This is
    needed for the iteration later.
    """
    # This should be a more restricted verification
    s = MyScyther(mpalist,claimid)
    claim = s.getClaim(claimid)
    if claim:
        if not claim.okay:
            # This is an MPA attack!
            print "I've found a multi-protocol attack on claim %s in the context %s." % (claimid,str(mpalist))
            return False
    else:
        return True


def constructMPAlist(protocolset,claimid,mpalist,length,start,callback):
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
                if not constructMPAlist(protocolset,claimid,mpalist + [p],length,pn+1,callback):
                    return False
        return True
    else:
        # list is long enough: callback
        return callback(mpalist,claimid)
    

def findMPA(protocolset,protocol,claimid,maxcount=3):
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
        constructMPAlist(protocolset,claimid,[protocol],count,0,verifyMPAlist)
        count += 1
    return None


def findAllMPA(protocolset,maxcount=3):
    """
    Given a set of protocols, find multi-protocol attacks
    """

    # Find all correct claims in each protocol
    (protocolset,correct) = getCorrectIsolatedClaims(protocolset)
    # For all these claims...
    for (protocol,claimid) in correct:
        # Try to find multi-protocol attacks
        findMPA(protocolset,protocol,claimid,maxcount=3)


def main():
    """
    Simple test case with a few protocols
    """

    list = ['nsl3-broken.spdl','ns3.spdl','nsl3.spdl']
    print "Performing multi-protocol analysis for the following protocols:", list
    print
    findAllMPA(list)
    print
    print "Analysis complete."


if __name__ == '__main__':
    main()


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
