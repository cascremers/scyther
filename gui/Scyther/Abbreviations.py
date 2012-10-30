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
# Abbreviations
#
#
MINTERMSIZE = 10 # Hardcoded constant; but hard to enforce due to subterm replacements later
MINSTRUCTSIZE = 5 # Hardcoded constant for minimal size
#MAXTERMSIZE = 16 # Hardcoded constant (makes sense for ASCII matrices)
MAXTERMSIZE = 30 # Hardcoded constant (makes sense for graphviz graphs)
MAXREPLACE = 30  # More than 7 replacements need quadratic justification
REPLACECON = 2    # Constant for quadratic penalty

import Term
import Misc

def threshold(n):
    """
    threshold used to determine the threshold value for a given number of replacements n.
    """
    if n < 0:
        return [0,0,0]
    else:
        return [0.5 * (n**2),0,0]
    

class AbbrevContext(object):
    """
    Used to compute a single abbreviation that helps the most
    """

    def __init__(self):

        self.abbreviations = {}
        self.mapper = {}
        self.termlist = []
        self.subtermcount = []

    def isAbbrevCandidate(self,term):
        """
        True iff we might be abbreviated
        """
        global MAXTERMSIZE,MINTERMSIZE,MINSTRUCTSIZE

        if len(str(term)) < MINTERMSIZE:
            return False

        if term.getKeyAgents() != None:
            # We don't abbreviate simple keys, ever
            return False

        occ = self.subtermcount[str(term)]
        if occ > 1:
            return True

        if len(term.leaves()) < MINSTRUCTSIZE:
            return False

        return True

    def valAbbrevCandidate(self,term):
        """
        Higher is more likely to be abbreviated.
        Currently lexicographic-ish (occurrences, size)
        Returns n == -1 for non-candidates
        Returns n >= 0  for candidates
        """
        
        if not self.isAbbrevCandidate(term):
            return -1

        # Main criterion: string size * occurrences^2
        size = len(str(term))
        occ = self.subtermcount[str(term)]
        t1 = (occ**2) * size

        # Second criterion: structure size
        t2 = term.size()

        # Third criterion: tuples bad
        if isinstance(term,Term.TermTuple):
            t3 = 1
        else:
            t3 = 0

        return [t1,t2,t3]

    def termUnfold(self,term):
        """
        Undo abbreviations in the given term
        """
        last = None
        while last != str(term):
            last = str(term)
            term = term.replace(self.unfold)
        return term

    def findOrder(self):
        """
        Determine an order on the abbreviation keys

        Currently it works pretty well
        """
        unorderedkeys = set(self.abbreviations.keys())

        # Pre-compute dependencies
        depends = {}
        for k in self.abbreviations.keys():
            depends[k] = set([ str(t) for t in self.abbreviations[k].subterms() if str(t) in self.abbreviations.keys() ])

        # Partition the macros into layers.
        # Things in a layer only depend on things in previous layers.
        layers = []
        previouslayers = set()
        while len(unorderedkeys) > 0:
            layer = set()
            for k in unorderedkeys:
                if len(depends[k]-previouslayers) == 0:
                    layer.add(k)

            # Store layer
            layers.append(layer)
            previouslayers |= layer

            # Remove from todo list
            for k in layer:
                unorderedkeys.remove(k)

        # We now have things in layers, need to decide how to order inside a layer
        # Idea: 
        # - check how many things depend on them, delay things with more outgoing edges. 
        # - things with more dependencies have precedence
        #   (because a reader needs to backtrack further more often otherwise)

        orderedkeys = []
        for i in range(0,len(layers)):
            layer = layers[i]
            laternodes = set()

            kl = []
            for k in layer:
                # Compute outgoing
                outgoing = 0
                for ll in layers[(i+1):]:
                    outgoing += len([ n for n in ll if k in depends[n] ])
                kl.append([[-len(depends[k]),outgoing,self.abbreviations[k]],k])
            kl.sort()

            orderedkeys += [ k for [m,k] in kl ]

        return orderedkeys


    def replaceMap(self,k,newterm):
        """
        Replace k (string) name by new term
        """
        # Store new abbreviation
        self.abbreviations[str(newterm)] = self.abbreviations[k]
        del self.abbreviations[k]

        # Update
        renamer = {}
        renamer[k] = newterm
        # Update abbreviations
        for abk in self.abbreviations.keys():
            self.abbreviations[abk] = self.abbreviations[abk].replace(renamer)
        # Update mapper
        for mapk in self.mapper.keys():
            self.mapper[mapk] = self.mapper[mapk].replace(renamer)


    def abbreviate(self):
        """
        Try to abbreviate the 'worst' term.
        Return false if we ran out of options
        """
        global MAXREPLACE

        stlist = []
        for t in self.termlist:
            stlist += t.subterms()

        self.subterms = Misc.uniqstr(stlist)
        self.subtermcount = Misc.multiset(stlist)

        candlist = [ [self.valAbbrevCandidate(term.replace(self.mapper)),term ] for term in self.subterms ]
        th = threshold(len(self.abbreviations.keys()))

        ## For debugging only
        #print "Candidate list for threshold %s" % th
        #candlist.sort()
        #for [val,term] in candlist:
        #    print "  %s:\t%s" % (val,str(term))

        #print th
        vallist = [ [val,term] for [val,term] in candlist if val > th ]
        vallist.sort()
        if len(vallist) > 0:
            val = vallist[-1][0]
            bigterm = vallist[-1][1]

            bigtermString = str(bigterm)

            # New string
            abbreviationTerm = Term.TermConstant(self.newName(prefix="TMP"))
            abbreviationString = str(abbreviationTerm)

            # Store folding
            self.mapper[str(self.termUnfold(bigterm))] = abbreviationTerm
            # Store unfolding
            self.unfold[str(abbreviationTerm)] = bigterm

            # Local replacements
            abbrev = {}
            abbrev[bigtermString] = abbreviationTerm
            # Replace termlist
            ot = self.termlist[:]
            self.termlist = [t.replace(abbrev) for t in ot]
            ## Replace also in abbreviations
            for k in self.abbreviations.keys():
                self.abbreviations[k] = self.abbreviations[k].replace(abbrev)
            self.abbreviations[abbreviationString] = bigterm

            ## Add to termlist too
            #self.termlist += [bigterm]

            return True
        else:
            return False

    def abbreviateAll(self,termlist):
        """
        Repeatedly replace best candidate
        """
        global MAXREPLACE

        self.abbreviations = {}
        self.termlist = termlist[:]
        self.unfold = {}
        self.mapper = {}

        while True:
            if self.abbreviate() == False:
                break
        
        ## For debugging only
        #print "Mapper:"
        #for k in self.mapper.keys():
        #    print "%s -> %s" % (k,self.mapper[k])
        
        # The macros are now named/numbered in the order of their creation, which typically is different from
        # the order in which they appear in a trace. What's worse, M1 may have M3 as a subterm.
        # In order to avoid at least the latter case, we rename the macros at least in such a way that later macros only
        # depend on their predecessors.
        #
        # Find suitable order
        okl = self.findOrder()
        #print okl

        # Propagate order to numbererd naming scheme
        for k in okl:
            nn = self.newName()
            self.replaceMap(k,Term.TermConstant(nn))

        return self.abbreviations

    def select(self):

        self.bestval = None
        self.bestterm = None
        for term in self.subterms:
            occ = self.subtermcount[str(term)]
            val = self.valAbbrevCandidate(term)
            if val != None:
                if (self.bestterm == None) or (val > self.bestval):
                    self.bestterm = term
                    self.bestval = max(self.bestval,val)

        return (self.bestterm,self.bestval)

    def newName(self,prefix="M"):
        """
        Come up with a new name
        """

        cnt = 1
        
        substrings = [str(t) for t in self.subterms]
        substrings += self.abbreviations.keys()

        while ("%s%i" % (prefix,cnt)) in substrings:
            cnt += 1

        return "%s%i" % (prefix,cnt)


#---------------------------------------------------------------------------

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
