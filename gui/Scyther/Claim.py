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

    def getVerified(self):
        """
        returns an element of [None,'Verified','Falsified']
        """
        n = len(self.attacks)
        if self.state:
            # this is about reachability
            if n > 0:
                return "Verified"
            else:
                if self.complete:
                    return "Falsified"
        else:
            # this is about attacks
            if n > 0:
                return "Falsified"
            else:
                if self.complete:
                    return "Verified"
        return None

    def __str__(self):
        """
        Resulting string
        """
        s = "claim id [%s]" % (self.id)
        s+= " " + str(self.claimtype)
        if self.parameter:
            s+= " " + str(self.parameter)

        # determine status
        s+= " : "
        if self.okay:
            s+= "[Ok] "
        else:
            s+= "[Fail] "

        s+= " %i " % (self.failed)
        s+= self.stateName(self.failed)

        vt = self.getVerified()
        if vt:
            s+= " (%s)" % vt
        s+= " [%s]" % self.getComment()

        return s


