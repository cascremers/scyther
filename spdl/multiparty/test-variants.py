#!/usr/bin/python
#
#
#    Idea:
#
#    We test all variants [0..31] until we are sure they work. Thus,
#    we slowly refine the tests.
#
import commands

def startset():
    return range(0,32)
    
    mainlist = [11, 15]
    print "Starting with", mainlist
    return mainlist

def tuplingchoice(variant,P,runs,latupling):
    #    variant is in range [0..64>,
    #    where we use the highest bid to signify the
    #    associativity of the tupling.

    extraflags = ""
    if latupling:
        extraflags += " --la-tupling"

    s = "./multinsl-generator.py"
    s += " %i %s" % (P,variant)
    s += " | scyther -r%i --untyped %s" % (runs, extraflags)
    #s += " | scyther -a -r%i --summary" % runs
    #print s
    s += " | grep \"Fail\""
    out = commands.getoutput(s)
    if out == "":
        #print "Okay"
        return True
    else:
        #print out
        # Thus, MultiNSL P variant has the first attack for n runs
        return False

def testvariant(v,p,r):
    if not tuplingchoice (v,p,r, False):
        return False
    else:
        return tuplingchoice (v,p,r, True)

def removeattacks (testlist, P, runs):
    okaylist = []
    for v in testlist:
        if testvariant (v, P, runs):
            okaylist.append(v)
    return okaylist

def scan(testlist, P, runs):
    print "Testing using P %i and %i runs." % (P,runs)
    results = removeattacks (testlist, P, runs)
    if len(results) < len(testlist):
        attacked = []
        for i in range(0,len(testlist)):
            if testlist[i] not in results:
                attacked.append(testlist[i])
        print "Using P %i and %i runs, we find attacks on %s" % (P,runs, str(attacked))
        print "Therefore, we are left with %i candidates: " % (len(results)), results 

    return results

def main():
    candidates = startset()
    for P in range(3,7):
        for rundiff in range(0,5):
            candidates = scan(candidates,P,P+rundiff)

    print
    print "Good variants:"
    print candidates
        

main()
