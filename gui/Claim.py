#
# Claim
#

import Term

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

    def stateName(self,count=1):
        if self.state:
            s = "state"
        else:
            s = "attack"
        if count != 1:
            s += "s"
        return s

    def __str__(self):
        s = "claim id [%s]" % (self.id)
        s+= " " + str(self.claimtype)
        if self.parameter:
            s+= " " + str(self.parameter)

        # determine status
        s+= " : %i " % (self.failed)
        s+= self.stateName(self.failed)
        if self.complete:
            s+= " (complete)"

        return s


