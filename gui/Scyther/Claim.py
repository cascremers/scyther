#
# Claim
#

import Term

def stateDescription(okay,n=1,caps=False):
    if okay:
        s = "trace class"
        if n != 1:
            s += "es"
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
        colours = ['red',
                   'dark red',
                   'dark green',
                   'pale green']
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


    def __str__(self):
        """
        Resulting string
        """
        s = "claim id [%s], %s" % (self.id,self.claimtype)
        if self.parameter:
            s+= " %s" % self.parameter

        # determine status
        s+= "\t: %s" % self.getComment()

        return s


