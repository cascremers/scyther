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
# Attack
#

import Trace
import Term
#import Classification
from Misc import *

class Attack(object):
    def __init__(self):
        self.broken = []
        self.match = None
        self.initialKnowledge = []
        self.inverseKeys = []
        self.protocol = None
        self.semiTrace = Trace.SemiTrace()
        self.variables = []
        self.protocoldescr = {}
        self.id = None
        self.knowledge = None 
        self.untrusted = []
        self.typeflaws = False
        self.commandline = ''
        self.scytherDot = None
        self.claim = None       # refers to parent claim
    
    def getInvolvedAgents(self):
        result = []
        for run in self.semiTrace.runs:
            for agent in run.roleAgents.values():
                result.append(agent)
        return uniq(result)

    def buildKnowledge(self):
        if not self.knowledge:
            self.knowledge = Term.Knowledge(self)
            self.knowledge.buildKnowledge()
        
    def getPrecedingLabelSet(self,event):
        return self.protocoldescr[str(event.label[0])].getPrecedingLabelSet(event.label)
        
    def getPrecedingRoleSet(self,event):
        return self.protocoldescr[str(event.label[0])].getPrecedingRoleSet(event.label)
        
    #def classify(self):
    #    classification = Classification.Classification(self)
    #    classification.classifyClaims()
    #    classification.classifyInitiations()
    #    classification.classifyComplexity()
    #    classification.classifyTypeflaws()
    #    return classification
