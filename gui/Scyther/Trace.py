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
# Trace
#
from .Misc import *

class InvalidAction(TypeError):
    "Exception used to indicate that a given action is invalid"
    
class InvalidEvent(TypeError):
    "Exception used to indicate that a given event is invalid"

class SemiTrace(object):
    def __init__(self):
        self.runs = []
    
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
            return [x for x in event.preceding if x not in previous]
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
        preceding = [x for x in preceding if x not in previous]
        return preceding
    
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
            
class ProtocolDescription(object):
    def __init__(self,protocol):
        self.protocol = protocol
        self.roledescr = {}

    # Find event by label
    def findEvent(self,eventlabel,eventType=None):
        for (role,descr) in list(self.roledescr.items()):
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
        events = [x for x in events if isinstance(x,EventRead)]
        return [x.label for x in events]

    # Calculate the roles in preceding labelset that is all roles that
    # that are in the precedingEvents of a certain event
    def getPrecedingRoleSet(self,eventlabel):
        events = self.getPrecedingEvents(eventlabel)
        roles = uniq([x.run.role for x in events])
        return roles
    

    def __str__(self):
        s = ''
        for x in list(self.roledescr.values()):
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

    def __iter__(self):
        return iter(self.eventList)

    def getAgent(self):
        if self.intruder:
            return None
        return self.roleAgents[self.role]

    def getFirstAction(self):
        return self.eventList[0]

    def getLastAction(self):
        return self.eventList[-1]

    def collapseIntruder(self):
        """ TODO still working on this. """
        if self.intruder:
            shouldcollapse = False
            for ev in self:
                return

class Event(object):
    def __init__(self,index,label,follows):
        self.index = index
        self.label = label
        self.follows = follows
        self.run = None
        self.preceding = None
        self.rank = None
    
    def shortLabel(self):
        try:
            return self.label[len(self.label)-1]
        except:
            return str(self.label)

    def getBefore(self):
        result = []
        for event in self.run:
            if (event == self):
                return result
            result.append(event)
        # This should never happen
        assert(False)

class EventSend(Event):
    def __init__(self,index,label,follows,fr,to,message):
        Event.__init__(self,index,label,follows)
        self.fr = fr
        self.to = to
        self.message = message

    def __str__(self):
        if self.run.intruder:
            return "SEND(%s)" % self.message
        else:
            return "SEND_%s(%s,%s)" % (self.shortLabel(),self.to,self.message)

class EventRead(Event):
    def __init__(self,index,label,follows,fr,to,message):
        Event.__init__(self,index,label,follows)
        self.fr = fr
        self.to = to
        self.message = message
    
    def __str__(self):
        if self.run.intruder:
            return "READ(%s)" % self.message
        else:
            return "READ_%s(%s,%s)" % (self.shortLabel(),self.fr, self.message)

class EventClaim(Event):
    def __init__(self,index,label,follows,role,type,argument):
        Event.__init__(self,index,label,follows)
        self.role = role
        self.type = type
        self.argument = argument
        self.broken = None
    
    # A Claim should be ignored if there is an untrusted agent in the role
    # agents
    def ignore(self):
        for untrusted in self.run.attack.untrusted:
            if untrusted in list(self.run.roleAgents.values()):
                return True
        return False
        
    # Return (protocol,role)
    def protocolRole(self):
        return "(%s,%s)" % (self.run.protocol,self.run.role)
    
    def argstr(self):
        if self.argument == None:
            return '*'
        else:
            return str(self.argument)
            
    def __str__(self):
        return "CLAIM_%s(%s, %s)" % (self.shortLabel(),self.type,self.argstr())

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


