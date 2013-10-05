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
# Term
#
import Trace
from Misc import *

class InvalidTerm(TypeError):
    "Exception used to indicate that a given term is invalid"
    

class Knowledge(object):
    def __init__(self,attack):
        self.attack = attack
        self.knowledge = []

    def getInverse(self,term):
        for pair in self.attack.inverseKeys:
            if term == pair[0]:
                return pair[1]
            if term == pair[1]:
                return pair[0]

    # Get the inverse key
    def getInverseKey(self,term):
        # First try to see if the entire term has an inverse
        result = self.getInverse(term)
        if result != None:
            return result
        
        # If it is an apply term, try to see if the function has an inverse
        if isinstance(term,TermApply):
            result = self.getInverse(term.function)
            if result != None:
                return TermApply(result,term.argument)
            
        # No inverse found, so term is its own inverse
        return term
        
    # Add a term to the knowledge
    def add(self,term):
        if term == None:
            return
        added = False
        for x in term.deriveTerms(self):
            if not x in self.knowledge:
                added = True
                self.knowledge.append(x)
        
        # Something new was added, maybe this can help us to decrypt a term
        # that we could not decrypt before
        if added:
            for x in self.knowledge:
                if isinstance(x,TermEncrypt):
                    self.add(x)
            
    def canDerive(self,term):
        # We can derive free variables, because we can even choose them
        if isinstance(term,TermVariable) and term.isFree():
            return True
        # We can derive a term if it is in the knowledge
        # or all terms required to construct it are in the knowledge
        if exists(lambda x: x == term,self.knowledge):
            return True
        constructors = term.constructorTerms()
   
        if len(constructors) == 1 and constructors[0] == term:
            # This is a single term, there is no need to look at constructor
            # terms as we have already looked at the complete term
            return False
            
        return forall(lambda x: self.canDerive(x),constructors)
            
        
    # Knowledge is the initial knowledge and all messages in sends
    def buildKnowledge(self):
        self.knowledge = self.attack.initialKnowledge[:]
        for run in self.attack.semiTrace.runs:
            # Intruder actions do not add knowledge processing them
            # is a waste of time
            if run.intruder:
                continue
            for event in run:
                if isinstance(event,Trace.EventSend):
                    self.add(event.message)
                    self.add(event.fr)
                    self.add(event.to)

class Term(object):
    def __init__(self):
        self.types = None
        
    def __str__(self):
        raise InvalidTerm
    
    def constructorTerms(self):
        raise InvalidTerm

    def deriveTerms(self,knowledge):
        raise InvalidTerm
    
    # Two terms are equal when their string rep is equal
    def __cmp__(self,other):
        return cmp(str(self),str(other))
                
    
class TermConstant(Term):   
    def __init__(self, constant):
        Term.__init__(self)
        self.value = str(constant)
    
    def deriveTerms(self,knowledge):
        return [self]
        
    def constructorTerms(self):
        return [self]
    
    def __str__(self):
        return self.value

class TermEncrypt(Term):
    def __init__(self, value, key):
        Term.__init__(self)
        self.value = value
        self.key = key

    def deriveTerms(self,knowledge):
        # In order to unpack an encrypted term we have to have the inverse key
        inverse = knowledge.getInverseKey(self.key)
        if knowledge.canDerive(inverse):
            return [self] + [self.value] + self.value.deriveTerms(knowledge)
        else:
            return [self]
        
    def constructorTerms(self):
        return [self.value,self.key]
        
    def __str__(self):
        return "{%s}%s" % (self.value, self.key)

class TermApply(Term):
    def __init__(self, function, argument):
        Term.__init__(self)
        self.function = function
        self.argument = argument

    def constructorTerms(self):
        return [self.function,self.argument]
        
    def deriveTerms(self,knowledge):
        return [self]

    def __str__(self):
        return "%s(%s)" % (self.function, self.argument)

class TermVariable(Term):
    def __init__(self, name, value):
        Term.__init__(self)
        self.name = name
        self.value = value

    def isFree(self):
        return self.value == None
    
    def constructorTerms(self):
        if self.value != None:
            return [self.value]
        else:
            return [self.name]
    
    def deriveTerms(self,knowledge):
        if self.value != None:
            return [self,self.value] + self.value.deriveTerms(knowledge)
        else:
            return [self,self.name]
    
    def __str__(self):
        if (self.value != None):
            return str(self.value)
        else:
            return str(self.name)

class TermTuple(Term):
    def __init__(self, op1, op2):
        Term.__init__(self)
        self.op1 = op1
        self.op2 = op2

    def __str__(self):
        return "%s,%s" % (self.op1,self.op2)
    
    def constructorTerms(self):
        return [self.op1,self.op2]
        
    def deriveTerms(self,knowledge):
        return [self,self.op1,self.op2]+self.op1.deriveTerms(knowledge)+self.op2.deriveTerms(knowledge)
        
    def __getitem__(self,index):
        if index == 0:
            return self.op1
        elif index == 1:
            return self.op2
        else:
            return self.op2.__getitem__(index-1)

