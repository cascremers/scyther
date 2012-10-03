"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2012 Cas Cremers

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
# Trace
#
from Misc import *
import Term

CLAIMRUN = 0    # Hardcoded constant for claiming run
RUNIDMAP = {}
MAXTERMSIZE = 16 # Hardcoded constant

def permuteRuns(runstodo,callback,sequence=None):
    """
    Perform callback on all possible permutations of the runs.
    The callback can return a sequence, these are concatenated.

    Special:
    - Neighbouring grouped runs are in increasing ID order
    - Helper runs are omitted

    Sequence == None is a special setup command that gets rid of hidden runs

    run.vistype:
      "HIDDEN", None (== unique), and grouped names (e.g. "intruder")

    """
    # Init
    if sequence == None:
        seq = [run for run in runstodo if not run.vistype == "HIDDEN"]
        permuteRuns(seq,callback,[])
        return

    # Nothing left
    if len(runstodo) == 0:
        return callback(sequence)

    for run in runstodo:
        # Not a hidden run by construction
        skip = False

        # Ensure neighbouring grouped runs are increasing in run ID
        if (run.vistype != None) and (run.vistype != "HIDDEN"):
            if len(sequence) > 0:
                if sequence[-1].vistype == run.vistype:
                    if sequence[-1].id > run.id:
                        skip = True

        # Iterate
        if skip == False:
            seq = [r for r in runstodo if r != run]
            #print "Hi", len(runstodo), len(seq)
            permuteRuns(seq,callback,sequence=sequence + [run])

    return


def permuteMinimalCost(runstodo,callcost,takeFirst=False):
    global bestseq, bestcost

    bestseq = None
    bestcost = None

    permuteMinimalCostIterate(runstodo,callcost,takeFirst=takeFirst)

    return bestseq

def permuteMinimalCostIterate(runstodo,callcost,sequence=None,takeFirst=False):
    """
    Perform callback on all possible permutations of the runs.
    Minimizes cost function

    Special:
    - Neighbouring grouped runs are in increasing ID order
    - Helper runs are omitted

    Sequence == None is a special setup command that gets rid of hidden runs

    run.vistype:
      "HIDDEN", None (== unique), and grouped names (e.g. "intruder")

    """
    global bestseq, bestcost

    # Cutter
    if (takeFirst == True) and (bestcost != None):
        return

    # Init
    if sequence == None:
        seq = [run for run in runstodo if not run.vistype == "HIDDEN"]
        permuteMinimalCostIterate(seq,callcost,[])
        return

    # Still okay?
    cost = callcost(sequence)
    
    # Nothing left
    if len(runstodo) == 0:
        better = True
        if bestcost != None:
            if cost >= bestcost:
                better = False
        if better:
            bestcost = cost
            bestseq = [r for r in sequence]
            print "Cheaper solution with len %i and cost %i" % (len(bestseq),cost)

    # Premature cut?
    if bestcost != None:
        if cost >= bestcost:
            return

    for run in runstodo:
        # Not a hidden run by construction
        skip = False

        # Ensure neighbouring grouped runs are increasing in run ID
        if (run.vistype != None) and (run.vistype != "HIDDEN"):
            if len(sequence) > 0:
                if sequence[-1].vistype == run.vistype:
                    if sequence[-1].id > run.id:
                        skip = True

        # Iterate
        if not skip:
            seq = [r for r in runstodo if r != run]
            #print "Hi", len(runstodo), len(seq)
            permuteMinimalCostIterate(seq,callcost,sequence=sequence + [run])

    return


def colCompress(sequence):
    """
    Turns a sequence of runs into a sequences of run sequences, joining groups and omitting "HIDDEN"
    """
    newseq = []
    column = []
    for run in sequence:
        if run.vistype != "HIDDEN":
            if run.vistype == None:
                if len(column) > 0:
                    newseq.append(column)
                    column = []
                newseq.append([run])
            else:
                # Possibly groupable run
                if len(column) == 0:
                    column = [run]
                else:
                    # There's something in buf
                    if run.vistype == column[0].vistype:
                        # Same type
                        column.append(run)
                    else:
                        # Switch to new type
                        newseq.append(column)
                        column = [run]
    # Flush
    if len(column) > 0:
        newseq.append(column)

    return newseq
            


def ridColMap(cseq):
    """
    Takes a sequence of sequence of runs and turns them into a map from run ids to columns
    """
    ridmap = {}
    col = 0
    for clist in cseq:
        for run in clist:
            ridmap[run.id] = col
        col += 1
    return ridmap




def SaneRunID(runid):
    """
    Function to rewrite Scyther's internal run identifiers to something that humans like.
    """
    global RUNIDMAP

    k = str(runid)
    if k in RUNIDMAP.keys():
        return RUNIDMAP[k]
    else:
        return runid

class InvalidAction(TypeError):
    "Exception used to indicate that a given action is invalid"
    
class InvalidEvent(TypeError):
    "Exception used to indicate that a given event is invalid"


class AbbrevContext(object):
    """
    Used to compute a single abbreviation that helps the most
    """

    def __init__(self,termlist):

        self.termlist = termlist
        self.subterms = None

    def setup(self):

        if self.subterms != None:
            return

        self.subterms = []
        self.subtermcount = {}
        for t in self.termlist:
            stlist = t.subterms()
            for st in stlist:
                if str(st) not in self.subtermcount.keys():
                    self.subterms.append(st)
                    self.subtermcount[str(st)] = 1
                else:
                    self.subtermcount[str(st)] += 1

    def isCandidate(self,term):
        """
        True iff we might be abbreviated
        """
        global MAXTERMSIZE

        ts = term.size()
        if ts <= 1:
            return False
        if ts > 6:
            return True
        if len(str(term)) > MAXTERMSIZE:
            return True
        if (len(str(term)) > 6) and (self.subtermcount[str(term)] > 2):
            return True
        return False

    def valCandidate(self,term):
        """
        Higher is better.
        Currently lexicographic-ish (occurrences, size)
        """
        occ = self.subtermcount[str(term)]
        size = len(str(term))
        val = (20 * occ) + size
        return val

    def select(self):

        self.setup()

        bestval = None
        bestterm = None
        for term in self.subterms:
            if self.isCandidate(term):
                val = self.valCandidate(term)
                if bestterm == None:
                    bestval = val
                    bestterm = term
                elif val > bestval:
                    bestval = val
                    bestterm = term

        return bestterm




class Matrix(object):

    def __init__(self,trace):
        self.width = 0
        self.data = {}  # Map coordinates (x,y) to elements
        self.trace = trace
        self.result = None

    def mset(self,x,y,d):
        self.data[(x,y)] = d

    def mget(self,x,y):
        if (x,y) in self.data.keys():
            return self.data[(x,y)]
        else:
            return ""

    def getWidth(self):
        (x,y) = max(self.data.keys(), key=lambda x: x[0])
        return 1 + x

    def getHeight(self):
        (x,y) = max(self.data.keys(), key=lambda x: x[1])
        return 1 + y

    def insertAxes(self,comprCol):
        for x in range(0,len(comprCol)):
            runs = comprCol[x]
            if len(runs) == 1:
                if runs[0].isAgentRun():
                    for miny in range(0,self.getHeight()):
                        if self.mget(x,miny) != "":
                            break
                    for maxy in range(self.getHeight()-1,-1,-1):
                        if self.mget(x,maxy) != "":
                            break
                    for y in range(miny,maxy+1):
                        if self.mget(x,y) == "":
                            self.mset(x,y,"|")

    def compute(self):
        """
        Experimental matrix output
        """
        global checked,bestseq,bestcost
        global RUNIDMAP

        bestseq = None
        bestcost = 0
        checked = 0

        # Mark grouping
        for run in self.trace.runs:
            if run.intruder:
                run.vistype = "INTRUDER"
            elif run.isHelperRun():
                run.vistype = "INTRUDER"
            else:
                run.vistype = None

        # Determine best order
        def checkSolution(sequence):
            global checked,bestseq,bestcost

            checked += 1
            cost = self.trace.sequenceCost(sequence)
            if bestseq != None:
                if cost >= bestcost:
                    return

            bestseq = [x for x in sequence]
            bestcost = cost

        #permuteRuns(self.trace.runs,checkSolution)
        bestseq = permuteMinimalCost(self.trace.runs,self.trace.sequenceCost,takeFirst=True)
        print "Checked: %i" % (checked)

        # Compressed columns representation
        comprCol = colCompress(bestseq)
        colwidths = {}
        numcols = len(comprCol)
        for i in range(0,numcols):
            mw = 0
            for run in comprCol[i]:
                w = run.maxWidth()
                if w > mw:
                    mw = w
            colwidths[i] = mw

        # Construct
        myorder = self.trace.lineariseTrace()

        # Construct sane runidmap
        seen = []
        runid = 1
        for ev in myorder:
            if ev.run in seen:
                continue
            seen.append(ev.run)
            if ev.run.isAgentRun():
                RUNIDMAP[str(ev.run.id)] = runid
                runid += 1

        Term.pushRewriteStack(SaneRunID)

        # Abbreviations
        self.trace.abbreviate()

        # Put in
        seen = []   # Runs observed
        my = 0
        for y in range(0,len(myorder)):
            ev = myorder[y]
            x = None
            for i in range(0,numcols):
                if ev.run in comprCol[i]:
                    cell = []
                    # Header?
                    if ev.run not in seen:
                        cell += ev.run.matrixHead()
                        seen.append(ev.run)
                    # Append event if needed
                    skip = False
                    if ev.compromisetype != None:
                        if not self.trace.hasOutgoingEdges(ev):
                            skip = True
                    if not skip:
                        cell += [ev.matrix()]
                    # Store column
                    x = i

            for j in range(0,len(cell)):
                if cell[j] != "":
                    self.mset(x,my,cell[j])
                    my += 1

        # Current matrix has one element per line
        #
        # TODO: We may want to join up some lines

        # Insert vertical lines
        self.insertAxes(comprCol)

        # Display
        res = ""
        for y in range(0,self.getHeight()):
            for x in range(0,numcols):
                s = self.mget(x,y)
                if s != "---":
                    s = s + " " * (1 + colwidths[x] - len(s))
                else:
                    s = ("-" * (colwidths[x])) + " "

                res += s
            res += "\n"

        Term.popRewriteStack()

        return res


    def __str__(self):
        if self.result == None:
            self.result = self.compute()

        return self.result


class SemiTrace(object):
    def __init__(self):
        self.runs = []
        self.comments = ""
    
    def totalCount(self):
        count = 0
        for run in self.runs:
            count += len(run.eventList)
        return count
            
    def sortActions(self,actionlist):
        newlist = actionlist[:]
        newlist.sort(lambda x,y: self.getOrder(x,y))
        return newlist

    def getEnabled(self,previous):
        enabled = []
        for run in self.runs:
            for event in run:
                if event in previous or event in enabled:
                    continue
                prec = self.getPrecedingEvents(event,previous)
                if len(prec) == 0:
                    enabled.append(event)
        return enabled
          
    def collectTerms(self):
        # Determine relevant terms
        terms = []
        for run in self.runs:
            for ev in run.eventList:
                if not self.ignoreEvent(ev):
                    if ev.message != None:
                        terms.append(ev.message)
        return terms

    def newName(self,subterms):
        """
        Come up with a new name
        """
        pref = "M"
        cnt = 1
        
        substrings = [str(t) for t in subterms]

        while ("%s%i" % (pref,cnt)) in substrings:
            cnt += 1

        return "%s%i" % (pref,cnt)

    def replace(self,abbrev):
        for run in self.runs:
            for ev in run.eventList:
                if ev.message != None:
                    ev.message = ev.message.replace(abbrev)

    def abbreviate(self):
        """
        Abbreviate some stuff
        """
        abbreviations = {}
        abkeys = []
        while True:
            ss = self.collectTerms()
            AC = AbbrevContext(ss)
            ab = AC.select()
            if ab == None:
                break

            nn = self.newName(ss)
            abkeys.append(nn)
            abbrev = {}
            abbrev[str(ab)] = Term.TermConstant(nn)
            self.replace(abbrev)
            for k in abbreviations.keys():
                abbreviations[k] = abbreviations[k].replace(abbrev)
            abbreviations[nn] = ab
        
        for k in abkeys:
            self.comments += "Abbreviation: %s = %s\n" % (k, str(abbreviations[k]))

        # For debugging
        #res = ""
        #for t in ss:
        #    res += "%s; " % str(t)
        #res += "\n"
        #self.comments += res


    def ignoreEvent(self,ev):
        global CLAIMRUN

        # See if we should ignore this event in the context of this trace
        if isinstance(ev,EventClaim):
            if ev == self.getRun(CLAIMRUN).getLastAction():
                return True
        elif ev.compromisetype != None:
            if not self.hasOutgoingEdges(ev):
                return True
        elif ev.run.intruder:
            # Intruder: we ignore some parts of I_E and I_D
            if "I_E" in ev.run.role:
                if ev.index != 2:
                    return True
            if "I_D" in ev.run.role:
                if ev.index != 0:
                    return True

        return False

    # Returns run,index tuples for all connections
    def getConnections(self,event,removeIntruder=False):
        if not removeIntruder:
            return event.follows
        result = []
        if event.run.intruder:
            for before in event.getBefore():
                result.extend(self.getConnections(before,removeIntruder))

        for x in event.follows:
            fol = self.getEvent(x)
            # If this is an intruder action descend into it
            if fol.run.intruder:
                result.extend(self.getConnections(fol,removeIntruder))
            else:
                result.append(x)
        return uniq(result)
        
    # Return the minimum set of preceding events for a given event
    # that is the events before this event in the same run and all
    # actions required by the partional ordering
    # If previous is non empty remove all events already in previous
    def getPrecedingEvents(self,event,previous=[]):
        # If it is cached return cached version
        if event.preceding != None:
            return filter(lambda x: x not in previous,event.preceding)
        preceding = []
        for prec in event.getBefore():
            preceding.append(prec)
            preceding.extend(self.getPrecedingEvents(prec))
        for x in event.follows:
            fol = self.getEvent(x)
            preceding.append(fol)
            preceding.extend(self.getPrecedingEvents(fol))
        preceding = uniq(preceding)
        event.preceding = preceding
        preceding = filter(lambda x: x not in previous,preceding)
        return preceding

    def hasOutgoingEdges(self,event):
        """
        Determine if an event has outgoing edges.
        """
        if not(isinstance(event,EventSend)):
            # Not a send, so can't be.
            return False

        # Local shortcuts
        runid = event.run.id
        evid = (runid,event.index)

        # Now scan all other runs
        for run in self.runs:
            if run.id != runid:
                for ev in run.eventList:
                    if evid in ev.follows:
                        return True
        return False
    
    # Returns -1 if the first event has to be before the second one
    #         +1 if the second event has to be before the first one
    #          0 if there is no order defined on the two events 
    def getOrder(self,event1,event2):
        if (event1 in self.getPrecedingEvents(event2)):
            return -1
        if (event2 in self.getPrecedingEvents(event1)):
            return 1
        return 0
    
    # Get event by run id and index
    def getEvent(self,idx):
        (rid,index) = idx
        for run in self.runs:
            if run.id != rid:
                continue
            for event in run:
                if event.index == index:
                    return event
        raise InvalidEvent
    
    # Get all claim events in the trace
    def getClaims(self):
        claims = []
        for run in self.runs:
            for event in run:
                if isinstance(event,EventClaim):
                    claims.append(event)
        return claims

    # Returns a list of all initiation events in the semitrace
    def getInitiations(self):
        initiations = []
        for run in self.runs:
            # Initiations are runs of honest agents
            if (run.intruder):
                continue
            # Which contain no recvs before the first send
            for action in run:
                if (isinstance(action,EventRead)):
                    break
                elif (isinstance(action,EventSend)):
                    initiations.append(action)
                    break
        return initiations

    # Get all runs performed by a specific agent
    def getAgentRuns(self,agent):
        result = []
        for run in self.runs:
            if run.getAgent() == agent:
                result.append(run)
        return result

    # Return a list of all runs that are parallel with this run
    def getParallelRuns(self,run):
        parallel = []
        first = run.getFirstAction()
        # Process all events that are before the end of the run
        for event in self.getPrecedingEvents(run.getLastAction()):
            # Only count those we haven't found yet
            if event.run in parallel or event.run == run:
                continue
            # If the event is also after the beginning of the run it is
            # parallel
            if self.getOrder(event,first) == 1:
                parallel.append(event.run)
        return parallel

    def getRun(self,runid):
        for run in self.runs:
            if run.id == runid:
                return run
        return None

    def lineariseTrace(self):
        # Determine which events need to be shown
        todo = []
        for run in self.runs:
            for ev in run.eventList:
                todo.append(ev)

        myorder = []
        while len(todo) > 0:
            """
            Wait until we run out of candidates.
            Note we consider non-regular runs to be atomic
            """
            # First find out which are the candidates to go first
            first = []
            for n1 in todo:

                canGoFirst = True

                # Compensate for non-agent run atomicity
                if n1.run.isAgentRun():
                    x1 = n1
                else:
                    x1 = n1.run.getLastAction()

                for n2 in todo:
                    if n1.run.id != n2.run.id:

                        # Compensate for non-agent run atomicity
                        if self.getOrder(x1,n2) == 1:
                            canGoFirst = False
                            break

                if canGoFirst == True:
                    first.append(n1)

            # One has to be possible
            assert(len(first) > 0)

            # Select a candidate
            ev = first[0]


            # The main issue: Append event(s)
            # Note that we need to deal with atomicity
            if ev.run.isAgentRun():
                toadd = [ev]
            else:
                toadd = ev.run.eventList

            for ev in toadd:
                myorder.append(ev)
                # Mark done
                todo.remove(ev)

        return myorder

    def __str__(self,protocoldescr=None):
        """
        Visualize the semi-trace

        We have a number of runs with eventlists.
        We want to linearize and explain them.

        Tuples: runid x index

        If we are given the protocol description, we can say a bit more.
        """
        global RUNIDMAP

        # Determine the relevant claim
        if len(self.runs) > 0:
            # TODO: Pretty hardcoded stuff, could be much nicer
            global CLAIMRUN

            claimev = self.getRun(CLAIMRUN).getLastAction()
        else:
            claimev = None

        myorder = self.lineariseTrace()

        # Construct sane runidmap
        seen = []
        runid = 1
        for ev in myorder:
            if ev.run in seen:
                continue
            seen.append(ev.run)
            if ev.run.isAgentRun():
                RUNIDMAP[str(ev.run.id)] = runid
                runid += 1

        Term.pushRewriteStack(SaneRunID)

        # Abbreviations
        self.abbreviate()

        # Display events in the chosen order
        # Construct table headers
        res = ""    # Buffer for the returned result string
        # Add initial comments
        res += self.comments
        if len(res) > 0:
            res += "\n"

        res += "Step\tRun\tDescription\n"
        res += "\n"

        line = 1    # Line counter
        seen = []   # Runs we have already seen

        for ev in myorder:

            # Display headers for new things
            if ev.run in seen:
                # Already seen before
                pass
            else:
                # Run not seen before, so store run
                seen.append(ev.run)
                if ev.run.intruder == True:
                    # Intruder action
                    # TODO: We probably need Scyther to mark function applications here
                    # TODO: We need Scyther to mark long-term private keys,state, etc to see reveals or compromise
                    if "I_E" in str(ev.run.role):
                        agent = ev.run.getLKRagent()
                        if agent == None:
                            # Construction
                            msg = str(ev.run.eventList[2].message)
                            res += "%i\t\tThe adversary constructs %s.\n" % (line,msg)
                            line += 1
                        else:
                            # Long-term key reveal
                            msg = str(ev.run.eventList[2].message)
                            res += "%i\t\tLong-term key reveal of %s.\n" % (line,msg)
                            line += 1
                    elif "I_D" in str(ev.run.role):
                        # Deconstruction
                        msg = str(ev.run.eventList[0].message)
                        mrs = str(ev.run.eventList[2].message)
                        res += "%i\t\tThe adversary decrypts %s to obtain %s.\n" % (line,msg,mrs)
                        line += 1
                    elif "I_M" in str(ev.run.role):
                        # Initial knowledge
                        pass
                    elif "I_R" in str(ev.run.role):
                        res += "%i\t\tThe adversary knows %s.\n" % (line,str(ev.run.eventList[0].message))
                        line += 1
                    else:
                        # Unknown
                        res += "%i\t\tProtocol %s, role %s. " % (line,ev.run.srid(), ev.run.protocol, ev.run.role)
                        res += "'intruder': %s.\n" % (ev.run.intruder)
                        line += 1
                else:
                    # Not an intruder run
                    if ev.run.isAgentRun():
                        # Normal agent run
                        actor = ev.run.getAgent()
                        prot = ev.run.protocol
                        role = ev.run.role
                        res += "%i\t%s\t%s creates a run of protocol %s in role %s. " % (line,ev.run.srid(),actor,prot,role)

                        otherroles = ev.run.roleAgents.keys()
                        otherroles.remove(ev.run.role)
                        res += "%s assumes " % (actor)
                        res += ev.run.getAssumptions()
                        res += ".\n"
                        line += 1
                    elif ev.run.isHelperRun():
                        # Helper run
                        msg = ev.run.getLastAction().message
                        res += "%i\t\tThe adversary derives %s (using helper %s,%s).\n" % (line,msg,ev.run.protocol,ev.run.role)
                        
            # Display the concrete event if needed
            if ev.run.intruder == False:
                # Normal run
                if not ev.run.isHelperRun():
                    # Not a helper protocol
                    relevant = True
                    if str(ev).startswith("CLAIM"):
                        if ev != claimev:
                            relevant = False

                    if relevant:
                        if ev.compromisetype == None:
                            # Normal event
                            res += "%i\t%s\t%s.\n" % (line,ev.run.srid(),str(ev))
                            line += 1
                        else:
                            # Compromise
                            if self.hasOutgoingEdges(ev):
                                compromiseTypes = { "SSR":"Session-state", "SKR":"Session-key", "RNR":"Random" }
                                if ev.compromisetype in compromiseTypes.keys():
                                    res += "%i\t%s\t%s reveal of %s.\n" % (line,ev.run.srid(),compromiseTypes[ev.compromisetype],str(ev.message))
                                    line += 1
                                else:
                                    res += "%i\t%s\tReveal of %s (unknown reveal type).\n" % (line,ev.run.srid(),str(ev.message))
                                    line += 1
                            else:
                                # Skip because compromise without outgoing edges
                                pass
                else:
                    # Helper protocol
                    pass    # skip

        Term.popRewriteStack()

        # Return the result
        return res


    def countCrossings(self,cseq,weightmap={}):
        """
        Processes a sequence of sequences of runs (the compressed sequence of columns->run sets)

        For now, we are not supporting "HIDDEN" well.
        The output of this function is only meaningful if there are no vistype=="HIDDEN" nodes.

        Weightmap assigns weights to vistypes. Note that the weights default to 1.
        """
        global crossings

        # Map run id's to columns
        ridmap = ridColMap(cseq)
        
        # Sequence maps indices to non-helper runs
        crossings = 0

        def countJumps(srccol,dstcol,weightmap):
            global crossings

            if dstcol > srccol:
                mincol = srccol
                maxcol = dstcol
            else:
                mincol = dstcol
                maxcol = srccol
            for i in range(mincol+1,maxcol):
                mrun = cseq[i]
                if mrun.vistype in weightmap.keys():
                    crossings += weightmap[mrun.vistype]
                else:
                    crossings += 1
        
        # Iterate over all bindings
        for clist in cseq:
            for run in clist:
                if run.vistype == "HIDDEN":
                    continue
                dstcol = ridmap[run.id]
                for evd in run.eventList:
                    for x in evd.follows:
                        evs = self.getEvent(x)
                        if evs.run == run:
                            continue
                        if evs.run.vistype == "HIDDEN":
                            continue
                        try:
                            srccol = ridmap[evs.run.id]
                            countJumps(srccol,dstcol,weightmap)
                        except:
                            pass

        return crossings

    def sequenceCost(self,sequence):
        """
        Determine cost based on "islands" and crossings.
        "islands" are covered by length of the compressed sequence
        """
        cseq = colCompress(sequence)
        weightmap = {}
        weightmap["INTRUDER"] = 0.2
        weightmap["HIDDEN"] = 0
        cost = self.countCrossings(cseq,weightmap)
        clen = len(cseq)

        return cost + (5 * clen)



    def matrix(self):
        """
        Experimental matrix output
        """

        res = ""

        # Add initial comments
        res += self.comments
        if len(res) > 0:
            res += "\n"

        m = Matrix(self)

        res += str(m)

        print res
                



            
class ProtocolDescription(object):
    def __init__(self,protocol):
        self.protocol = protocol
        self.roledescr = {}

    # Find event by label
    def findEvent(self,eventlabel,eventType=None):
        for (role,descr) in self.roledescr.items():
            for event in descr:
                if event.label == eventlabel:
                    if eventType == None or isinstance(event,eventType):
                        return event

    # Return all events that should have occured before the given event
    # if the protocol is executed exactly as specified 
    # (i.e. all previous events in the same run and the preceding events
    # of the matching sends of all reads)
    def getPrecedingEvents(self,eventlabel,eventType=None):
        event = self.findEvent(eventlabel,eventType)
        if event.preceding != None:
            return event.preceding
        preceding = event.getBefore()+[event]
        for prev in preceding:
            # For this event and all events that are before it in the run
            # description see if it is a read and if it is also add the
            # precedinglabelset of the matching send
            if (isinstance(prev,EventRead)):
                match = self.findEvent(prev.label,EventSend)
                if match:
                    preceding.extend(self.getPrecedingEvents(match.label,EventSend))
        preceding = uniq(preceding)
        event.preceding = preceding
        return preceding
    
    # Calculate the preceding labelset that is all read events
    # that are in the precedingEvents of a certain event
    def getPrecedingLabelSet(self,eventlabel):
        events = self.getPrecedingEvents(eventlabel)
        events = filter(lambda x: isinstance(x,EventRead),events)
        return [x.label for x in events]

    # Calculate the roles in preceding labelset that is all roles that
    # that are in the precedingEvents of a certain event
    def getPrecedingRoleSet(self,eventlabel):
        events = self.getPrecedingEvents(eventlabel)
        roles = uniq([x.run.role for x in events])
        return roles
    
    def __str__(self):
        s = ''
        for x in self.roledescr.values():
            for e in x:
                s += str(e) + "\n"
        return s

class Run(object):
    def __init__(self):
        self.id = None
        self.protocol = None
        self.role = None
        self.roleAgents = {}
        self.eventList = []
        self.intruder = False
        self.attack = None
        self.variables = []
        self.vistype = None     # "HIDDEN", None (== unique), or any string

    def __iter__(self):
        return iter(self.eventList)

    def srid(self):
        # Sane run id
        return SaneRunID(self.id)

    def isHelperRun(self):
        if self.intruder == True:
            return False
        if str(self.protocol).startswith("@"):
            return True
        return False

    def isAgentRun(self):
        if self.intruder == True:
            return False
        return not self.isHelperRun()

    def getAgent(self):
        if self.intruder:
            return None
        return self.roleAgents[self.role]

    def getFirstAction(self):
        return self.eventList[0]

    def getLastAction(self):
        return self.eventList[-1]

    def getAssumptions(self):
        res = ""
        otherroles = self.roleAgents.keys()
        otherroles.remove(self.role)
        for ind in range(0,len(otherroles)):
            role = otherroles[ind]
            res += "%s->%s" % (role,self.roleAgents[role])
            if ind == len(otherroles) - 2:
                res += ", and"
            elif ind < len(otherroles) - 2:
                res += ", "
        return res

    def findProtocol(self,pdescr):
        """
        Find our protocol in a protocol description set
        """
        for prk in pdescr.keys():
            prot = pdescr[prk]
            if self.protocol == str(prot.protocol):
                return prot
        return None

    def collapseIntruder(self):
        """ TODO still working on this. """
        if self.intruder:
            shouldcollapse = False
            for ev in self:
                return

    def getLKRagent(self):
        # Determine if this is an LKR reveal. If so, return agent. If not, return None
        if "I_E" in str(self.role):
            # Construction
            if str(self.eventList[1].message) == 'sk':    # TODO hardcoded sk
                return self.eventList[0].message
        return None

    def matrixHead(self):
        # Return matrix head: array of single lines
        if not self.isAgentRun():
            if self.intruder:
                return [""]
            elif self.isHelperRun():
                return [""]
            else:
                return ["%s" % (self.role)]
        else:
            hd = ["---",
                  "Create run %i" % (self.srid()),
                  "%s in protocol %s, role %s" % (self.getAgent(),self.protocol,self.role),
                  "Assumes %s" % (self.getAssumptions()),
                  "---"
                    ]
            return hd

    def maxWidth(self):
        mw = 0
        column = self.matrixHead()
        for ev in self.eventList:
            column.append(ev.matrix())
        for l in column:
            w = len(l)
            if w > mw:
                mw = w
        return mw

class Event(object):
    def __init__(self,index,label,follows,compromisetype=None,bindinglist=[]):
        self.index = index
        self.label = label
        self.follows = follows
        self.run = None
        self.preceding = None
        self.rank = None
        self.compromisetype = compromisetype
        self.bindings = bindinglist
    
    def shortLabel(self):
        try:
            return self.label[len(self.label)-1]
        except:
            slabel = str(self.label)
            if "," in slabel:
                return slabel.split(",")[-1]
            else:
                return slabel


    def getBefore(self):
        result = []
        for event in self.run:
            if (event == self):
                return result
            result.append(event)
        # This should never happen
        assert(False)

    def __str__(self):
        return ""

    def matrix(self):
        if self.run.isAgentRun():
            return self.__str__()
        elif self.run.isHelperRun():
            # Helper
            if self.index == len(self.run.eventList) - 1:
                return "%s %s" % (self.run.protocol,self.message)
            else:
                return ""
        elif self.run.intruder :
            # Intruder run
            realindex = 0
            text = "Construct"
            if "I_E" in self.run.role:
                realindex = 2
            elif "I_D" in self.run.role:
                text = "Decrypt"
            elif "I_M" in self.run.role:
                text = "Initial knowledge"
            if self.index == realindex:
                return "%s %s" % (text,self.message)
            else:
                return ""
        else:
            return ""

class EventSend(Event):
    def __init__(self,index,label,follows,fr,to,message,compromisetype=None,bindinglist=[]):
        Event.__init__(self,index,label,follows,compromisetype=compromisetype,bindinglist=bindinglist)
        self.fr = fr
        self.to = to
        self.message = message

    def __str__(self):
        if self.run.intruder:
            return "SEND(%s)" % self.message
        else:
            return "SEND_%s(%s,%s)" % (self.shortLabel(),self.to,self.message)

class EventRead(Event):
    def __init__(self,index,label,follows,fr,to,message,compromisetype=None,bindinglist=[]):
        Event.__init__(self,index,label,follows,compromisetype=compromisetype,bindinglist=bindinglist)
        self.fr = fr
        self.to = to
        self.message = message
    
    def __str__(self):
        if self.run.intruder:
            return "RECV(%s)" % self.message
        else:
            return "RECV_%s(%s,%s)" % (self.shortLabel(),self.fr, self.message)

class EventClaim(Event):
    def __init__(self,index,label,follows,role,type,argument,compromisetype=None,bindinglist=[]):
        Event.__init__(self,index,label,follows,compromisetype=compromisetype,bindinglist=bindinglist)
        self.role = role
        self.type = type
        self.argument = argument
        self.message = argument     # Copy for display and term substitution (abbreviations)
        self.broken = None
    
    # A Claim should be ignored if there is an untrusted agent in the role
    # agents
    def ignore(self):
        for untrusted in self.run.attack.untrusted:
            if untrusted in self.run.roleAgents.values():
                return True
        return False
        
    # Return (protocol,role)
    def protocolRole(self):
        return "(%s,%s)" % (self.run.protocol,self.run.role)
    
    def argstr(self):
        if self.message == None:
            return '*'
        else:
            return str(self.message)
            
    def __str__(self):

        skip = True
        if self.run != None:
            if self.run.id == CLAIMRUN:
                if self.run.getLastAction() == self:
                    skip = False

        if skip == True:
            msg = ""
        else:
            msg = "CLAIM_%s(%s, %s)" % (self.shortLabel(),self.type,self.argstr())
        return msg


class EventIntruder(Event):
    """
    Intruder event extensions (allows for collapsing attacks later)
    """
    def __init__(self,follows,message,key,result):
        Event.__init__(self,0,None,follows)
        self.follows = follows
        self.message = message
        self.key = key
        self.result = result
        self.intruder = True

class EventDecr(EventIntruder):
    def __str__(self):
        return "DECR(%s, %s, %s)" % (self.message, self.key, self.result)

class EventEncr(EventIntruder):
    def __str__(self):
        return "ENCR(%s, %s, %s)" % (self.message, self.key, self.result)


