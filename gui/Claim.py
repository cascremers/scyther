#
# Claim
#

import Term

class Claim(object):
    def __init__(self):
        self.claimtype = None
        self.label = None
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

        # derived info
        self.foundstates = False
        self.foundproof = False

    def analyze(self):
        if str(self.claimtype) == 'Reachable':
            self.state = True
        if self.failed > 0:
            self.foundstates = True
        if self.complete:
            self.foundproof = True

    def stateName(self,count=1):
        if self.state:
            s = "state"
        else:
            s = "attack"
        if count != 1:
            s += "s"
        return s

    def __str__(self):
        s = "claim "
        s+= " " + str(self.protocol)
        s+= " " + str(self.role)

        # We need the rightmost thingy here
        label = self.label
        while isinstance(label,Term.TermTuple):
            label = label[1]

        s+= " " + str(label)
        s+= " " + str(self.claimtype)
        if self.parameter:
            s+= " " + str(self.parameter)

        # determine status
        s+= " : %i " % (self.failed)
        s+= self.stateName(self.failed)
        if self.complete:
            s+= " (complete)"

        return s


