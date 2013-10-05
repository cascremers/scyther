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

In this example, we find the differences between two different switch
settings for a large set of protocols.

The notification triggers if claim lists differ, or when a claim is okay
in one test but not in the other. Hence, we ignore differences between
complete/bounded verification.

Author: Cas Cremers


Define the strings below.

TEST0 is used for both, TEST1/2 define the difference between
the tests.
"""
#---------------------------------------------------------------------------

TEST0 = ""
TEST1 = "--max-runs=1"
TEST2 = "--max-runs=4"

#---------------------------------------------------------------------------

""" Import externals """
import commands

#---------------------------------------------------------------------------

""" Import scyther components """
from Scyther import Scyther

#---------------------------------------------------------------------------

def filterProtocol(protocol):
    """
    We may want to filter out some protocols.
    This function allows that. Return True if it is okay (and should be
    included) or False otherwise.
    """
    include = True
    return include

def simpleRun(args):
    x = Scyther.Scyther()
    x.options = args
    x.verify()
    return x

def ScytherRes(protocol,args=""):
    """
    Run Scyther on a protocol and return a tuple with the
    resulting object and claim list.
    """
    global TEST0

    args = "%s %s %s" % (TEST0, args, protocol)
    s = simpleRun(args)
    return (s,s.claims)


def findSameClaim(cl,claim):
    """
    Find in claim list the claim that corresponds to claim
    """
    for claim2 in cl:
        if claim2.id == claim.id:
            return claim2
    return None


def ScytherDiff(protocol):
    """
    Check whether the two different switch settings yield a different
    result.
    """
    global TEST1, TEST2

    (s1,cl1) = ScytherRes(protocol,TEST1)
    (s2,cl2) = ScytherRes(protocol,TEST2)

    res = ""
    if len(cl1) != len(cl2):
        res += "Different claim lists:\n%s\n%s\n" % (cl1,cl2)
    else:
        for claim1 in cl1:
            claim2 = findSameClaim(cl2,claim1)
            if claim2 == None:
                res += "%s not in second test.\n" % (claim1)
            else:
                if claim1.okay != claim2.okay:
                    res += "Different results:\n%s\n%s\n" % (claim1,claim2)

    if res == "":
        return None
    else:
        return res


def findProtocols():
    """
    Find a list of protocol names
    """

    cmd = "find -iname '*.spdl'"
    plist = commands.getoutput(cmd).splitlines()
    nlist = []
    for prot in plist:
        if filterProtocol(prot):
            nlist.append(prot)
    return nlist


def main():
    """
    Simple test case with a few protocols
    """
    global TEST0,TEST1,TEST2

    list = findProtocols()
    print "Performing delta analysis"
    print 
    print "String 0 (used for both): '%s'" % TEST0
    print "String 1: '%s'" % TEST1
    print "String 2: '%s'" % TEST2
    print
    print "After filtering, we are left with the following protocols:", list
    print
    maxcount = len(list)
    count = 1
    delta = 0
    for prot in list:
        perc = (100 * count) / maxcount
        print "[%i%%] %s: " % (perc,prot),
        res = ScytherDiff(prot)
        if res != None:
            print
            print "-" * 72
            print prot
            print "-" * 72
            print res
            delta = delta + 1
        else:
            print "No interesting delta found."
        count = count + 1

    print
    print "Analysis complete."
    print "%i out of %i protocols differed [%i%%]." % (delta,maxcount,(100 * delta)/maxcount)


if __name__ == '__main__':
    main()


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
