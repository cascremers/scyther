#!/usr/bin/python
#
#    Compare heuristics
#
import sys
from optparse import OptionParser

import scythertest

hurry = False    # True then branch and bound

# Parse
def parse(scout):
    """Parse Scyther output for heuristics tests

       in:
           A single Scyther output string (including newlines)
       out:
           ra:    number of failed claims
           rb:    number of bounded proofs of claims
           rc:    number of complete proofs of claims
           nc:    number of processed claims (should be the sum of the previous)
           st:    number of states traversed
    """
         
    ra = 0
    rb = 0
    rp = 0
    nc = 0
    st = 0
    timeout = False
    for l in scout.splitlines():
        data = l.split()
        if len(data) > 4 and data[0] == 'claim':
            # determine claim status
            tag = data[4]
            if tag == 'Fail':
                ra = ra + 1
                nc = nc + 1
            elif tag == 'Ok':
                nc = nc + 1
                if l.rfind("proof of correctness") != -1:
                    rp = rp + 1
                else:
                    rb = rb + 1
            # now count the states
            for d in data:
                if d.startswith("states="):
                    st = st + int(d[7:])
                if d.startswith("time="):
                    timeout = True

    return (ra,rb,rp,nc,st,timeout)


def test_goal_selector(goalselector, options,branchbound):
    """Test with a given goal selector

       in:
           goalselector:    as in Scyther docs.
           options:        options record (formatted as in optparse module)
       out:
           (attacks,bounds,proofs,claims,np,states)
           attacks:    number of failed claims
           bounds:    number of bounded proofs
           proofs:    number of complete proofs
           np:    number of protocols tested
           states:    total number of states explored.
    """

    import protocollist

    global hurry

    scythertest.set_extra_parameters("--count-states --heuristic=" + str(goalselector))
    result = str(goalselector)
    plist = protocollist.from_literature()
    np = len(plist)

    attacks = 0
    bounds = 0
    proofs = 0
    claims = 0
    states = 0
    timeouts = 0
    for p in plist:
        (status,scout) = scythertest.default_test([p], \
                int(options.match), \
                int(options.bounds))
        (ra,rb,rp,nc,st,timeout) = parse(scout)
        attacks = attacks + ra
        bounds = bounds + rb
        proofs = proofs + rp
        claims = claims + nc
        states = states + st
        if timeout:
            timeouts += 1


        if hurry and (bounds * states) > branchbound:
            return (-1,0,0,0,0,0)
    
    return (attacks,bounds,proofs,claims,np,states,timeouts)

# Max
class maxor:
    """Class for a dynamic maximum determination and corresponding formatting
    """

    def __init__(self,dir=0,mymin=99999999, mymax=-99999999):
        """Init

           in:
            dir:    bit 0 is set : notify of increase
                bit 1 is set : notify of decrease
            mymin:    initial minimum
            mymax:    initial maximum
        """

        self.dir = dir
        self.min = mymin
        self.max = mymax
        if dir & 1:
            self.data = mymax
        else:
            self.data = mymin
    
    def get(self):
        return self.data

    def reg(self,d):
        """Store a new data element

           in:
               element to be stored
           out:
               formatted element, plus increase/decrease
            notifications according to initial settings.
        """
        
        self.data = d
        res = ""
        if self.min >= d:
            if (self.dir & 2):
                res = res + "-"
            self.min = d
        if self.max <= d:
            if (self.dir & 1):
                res = res + "+"
            self.max = d
        if res == "":
            return res
        else:
            return "[" + res + "]"


# Main code
def main():
    parser = OptionParser()
    scythertest.default_options(parser)
    (options, args) = parser.parse_args()
    scythertest.process_default_options(options)

    print
    "G-sel\tAttack\tBound\tProof\tClaims\tTOuts\tProts\tStates\tBnd*Sts"
    print 

    ramax = maxor(1)
    rbmax = maxor(2)
    rpmax = maxor(1)
    statesmax = maxor(2)
    boundstatesmax = maxor(2)
    timeoutsmax = maxor(2)

    for g in range(1,15):
            (ra,rb,rp,nc,np,st,timeouts) = test_goal_selector(g, options,
                    boundstatesmax.get())

            res = str(g)
            if ra < 0:
                # Error: not well bounded
                res += "\tWent over bound, stopped investigation."
            else:
                boundstates = rb * st

                def shows (res, mx, data):
                    return res + "\t" + str(data) + mx.reg(data)

                res = shows (res, ramax, ra)
                res = shows (res, rbmax, rb)
                res = shows (res, rpmax, rp)
                res = res + "\t" + str(nc)
                res = shows (res, timeoutsmax, timeouts)
                res += "\t<%i>" % np
                res = shows (res, statesmax, st)
                res = shows (res, boundstatesmax, boundstates)

            print res
    print
    print "Goal selector scan completed."

# Only if main stuff
if __name__ == '__main__':
    main()
