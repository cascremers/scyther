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
           rp:    number of complete proofs of claims
           nc:    number of processed claims (should be the sum of the previous)
           st:    number of states traversed
    """
         
    ra = 0
    rb = 0
    rp = 0
    nc = 0
    st = 0
    to = 0
    for l in scout.splitlines():
        data = l.split()
        if len(data) > 4 and data[0] == 'claim':

            # Determine timeout, count states
            nc += 1
            timeout = False
            localstates = 0
            for d in data:
                if d.startswith("states="):
                    localstates += int(d[7:])
                if d.startswith("time="):
                    timeout = True

            # Only count the states if no timeout (otherwise not
            # dependable)
            ##if not timeout:
            ##    st += localstates
            st += localstates

            # Determine claim status
            tag = data[4]
            if tag == 'Fail':
                    ra += 1
            else:
                if not timeout:
                    if tag == 'Ok':
                        if l.rfind("proof of correctness") != -1:
                            rp += 1
                        else:
                            rb += 1
                    else:
                        print "Weird tag [%s] in line [%s]." % (tag, l)
                else:
                    to += 1

    return (ra,rb,rp,nc,st,to)


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

    scythertest.add_extra_parameters("--count-states --heuristic=" + str(goalselector))
    result = str(goalselector)

    # Selection of protocols
    ##plist = protocollist.from_literature()
    ##plist = protocollist.from_literature_no_problems()
    plist = protocollist.from_all()

    np = len(plist)

    attacks = 0
    bounds = 0
    proofs = 0
    claims = 0
    states = 0
    timeouts = 0
    undecidedprotocols = []
    for p in plist:
        (status,scout) = scythertest.default_test([p], \
                int(options.match), \
                int(options.bounds))
        (ra,rb,rp,nc,st,to) = parse(scout)
        claims += nc
        states += st
        timeouts += to
        attacks += ra
        bounds += rb
        proofs += rp
        # is something undecided for this protocol?
        if (rb > 0) or (to > 0):
            undecidedprotocols += [p]

        if hurry and (bounds * states) > branchbound:
            return (-1,0,0,0,0,0)
    
    return (attacks,bounds,proofs,claims,np,states,timeouts,undecidedprotocols)

# Max
class maxor:
    """Class for a dynamic maximum determination and corresponding formatting
    """

    def __init__(self,dir=0,mymin=9999999999, mymax=-9999999999):
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

    print "G-sel\tDecide\tAttack\tProof\tBound\tTOuts\tClaims\tProts\tStates\tBndTo*Sts"
    print 

    ramax = maxor(1)
    rbmax = maxor(2)
    rpmax = maxor(1)
    statesmax = maxor(2)
    boundstatesmax = maxor(2)
    timeoutsmax = maxor(2)
    decidemax = maxor(1)

    problems = {}
    sharedproblems = []
    firstproblem = True

    for g in range(1,8):
            (ra,rb,rp,nc,np,st,timeouts,prot_undec) = test_goal_selector(g, options,
                    boundstatesmax.get())

            res = str(g)
            if ra < 0:
                # Error: not well bounded
                res += "\tWent over bound, stopped investigation."
            else:
                undecided = rb + timeouts
                boundstates = undecided * undecided * st

                def shows (res, mx, data):
                    return res + "\t" + str(data) + mx.reg(data)

                decide = (100 * (ra + rp)) / nc
    
                res = shows (res, decidemax, decide)
                res += "%"
                res = shows (res, ramax, ra)
                res = shows (res, rpmax, rp)
                res = shows (res, rbmax, rb)
                res = shows (res, timeoutsmax, timeouts)
                res = res + "\t%i" % nc
                res += "\t%i" % np
                res = shows (res, statesmax, st)
                res = shows (res, boundstatesmax, boundstates)

            problems[g] = prot_undec
            if firstproblem:
                firstproblem = False
                sharedproblems = prot_undec
            else:
                nl = []
                for p in sharedproblems:
                    if p in prot_undec:
                        nl += [p]
                sharedproblems = nl

            print res
    print
    print "Goal selector scan completed."
    print
    print "%i shared problem protocols:" % len(sharedproblems)
    print sharedproblems
    print
    for g in problems.keys():
        print g, 
        print " has %i extra problems: " % (len(problems[g]) - len(sharedproblems)),
        print [ p for p in problems[g] if p not in sharedproblems ]
    print
    print

# Only if main stuff
if __name__ == '__main__':
    main()
