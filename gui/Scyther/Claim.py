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

#
# Claim
#

from . import Term

def stateDescription(okay,n=1,caps=False):
    if okay:
        s = "trace pattern"
        if n != 1:
            s += "s"
    else:
        s = "attack"
        if n != 1:
            s += "s"
    if caps:
        s = s[0].upper() + s[1:]
    return s


class Claim(object):
    def __init__(self):
        self.id = None          # a unique id string, consisting of 'protocol,label'
        self.claimtype = None
        self.label = None
        self.shortlabel = None
        self.protocol = None
        self.role = None
        self.parameter = None
        self.failed = 0
        self.count = 0
        self.states = 0
        self.complete = False
        self.timebound = False
        self.attacks = []
        self.state = False      # if true, it is a state, not an attack
        self.okay = None        # true if good, false if bad

        # derived info
        self.foundstates = False
        self.foundproof = False

    def analyze(self):

        # determine short label
        # We need the rightmost thingy here
        label = self.label
        while isinstance(label,Term.TermTuple):
            label = label[1]
        self.shortlabel = label

        # determine id
        self.id = "%s,%s" % (self.protocol,self.shortlabel)

        # some additional properties
        if str(self.claimtype) == 'Reachable':
            self.state = True
        if self.failed > 0:
            self.foundstates = True
        if self.complete:
            self.foundproof = True

        # status
        # normally, with attacks, okay means none
        self.okay = (self.failed == 0)
        if self.state:
            # but the logic reverses when it is states and not
            # attacks...
            self.okay = (not self.okay)

    def stateName(self,count=1,caps=False):
        return stateDescription(self.state,count,caps)

    def getRank(self):
        """
        Return claim rank
        0 - really failed
        1 - probably failed
        2 - probably okay
        3 - really okay
        """
        n = len(self.attacks)
        if not self.okay:
            # not okay
            if (self.state and self.complete) or ((not self.state) and (n > 0)):
                return 0
            else:
                return 1
        else:
            # okay!
            if not ((self.state and (n > 0)) or ((not self.state) and self.complete)):
                return 2
            else:
                return 3

    def getVerified(self):
        """
        returns an element of [None,'Verified','Falsified']
        """
        opts = ['Falsified',None,None,'Verified']
        return opts[self.getRank()]


    def getColour(self):
        """
        Returns a colour that expresses the state
        """
        colours = ['#FF0000',
                   '#800000',
                   '#005800',
                   '#00B000']
        return colours[self.getRank()]

    def getOkay(self):
        """
        Returns a very brief statement about the claim.

        Originally the two mid options had a question mark appended, but
        from a users' point of view this might only be more confusing,
        so I took them out again.
        """
        colours = ['Fail',
                   'Fail',
                   'Ok',
                   'Ok']
        return colours[self.getRank()]

    def getComment(self):
        """
        returns a sentence describing the results for this claim
        """
        n = len(self.attacks)
        atxt = self.stateName(n)
        remark = ""
        if not self.complete:
            if n == 0:
                # no attacks, no states within bounds
                remark = "No %s within bounds" % (atxt)
            else:
                # some attacks/states within bounds
                remark = "At least %i %s" % (n,atxt)
        else:
            if n == 0:
                # no attacks, no states
                remark = "No %s" % (atxt)
            else:
                # there exist n states/attacks (within any number of runs)
                remark = "Exactly %i %s" % (n,atxt)
        return remark + "."

    def triplet(self):
        """
        Return protocol,role,label triplet
        """
        return (self.protocol, self.role, self.shortlabel)

    def describe(self):
        s = str(self.claimtype)
        if self.parameter:
            s+= "(%s)" % self.parameter

        return s

    def roledescribe(self):
        return "%s: %s" % (self.role,self.describe())

    def __str__(self):
        """
        Resulting string
        """
        s = "claim id [%s], %s" % (self.id,self.describe())

        # determine status
        s+= "\t: %s" % self.getComment()

        return s


