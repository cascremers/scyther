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
