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
#MAXTERMSIZE = 16 # Hardcoded constant (makes sense for ASCII matrices)
MAXTERMSIZE = 30 # Hardcoded constant (makes sense for graphviz graphs)
MAXREPLACE = 7  # More than 7 replacements need quadratic justification
REPLACECON = 2    # Constant for quadratic penalty

import Term

def threshold(n):
    """
    threshold used to determine the threshold value for a given number of replacements n.
    """
    global MAXREPLACE, REPLACECON

    x = n - MAXREPLACE
    if x < 0:
        y = 0
    else:
        y = REPLACECON * (x**2)
    return y
    

class AbbrevContext(object):
    """
    Used to compute a single abbreviation that helps the most
    """

    def __init__(self):

        self.abbreviations = {}
        self.termlist = []

    def abbreviate(self):
        """
        Return false if we ran out of options
        """
        global MAXREPLACE
        import copy

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

        (ab,val) = self.select()
        if ab == None:
            return False

        # Now dermine of we can do it
        if val <= threshold(len(self.abbreviations.keys())):
            # Not worth the cost
            return False

        nn = self.newName()
        abbrev = {}
        abbrev[str(ab)] = Term.TermConstant(nn)
        # Replace termlist
        ot = copy.copy(self.termlist)
        self.termlist = [t.replace(abbrev) for t in ot]
        # Replace our own terms
        for k in self.abbreviations.keys():
            self.abbreviations[k] = self.abbreviations[k].replace(abbrev)
        self.abbreviations[nn] = ab

        return True

    def abbreviateAll(self,termlist):
        """
        Repeatedly replace best candidate

        tlfunc: Function from abbreviations to termlist
        replacefunc: Prodcedure to post-process an abbreviation (e.g. propagation)
        """
        global MAXREPLACE

        self.abbreviations = {}
        self.termlist = termlist

        while len(self.abbreviations.keys()) < MAXREPLACE:
            if self.abbreviate() == False:
                break

        return self.abbreviations

    def isCandidate(self,term):
        """
        True iff we might be abbreviated
        """
        global MAXTERMSIZE,MINTERMSIZE

        if len(str(term)) < MINTERMSIZE:
            return False
        if term.getKeyAgents() != None:
            # We don't abbreviate simple keys, ever
            return False
        ts = term.size()
        if (ts < 16) and isinstance(term.real(),Term.TermTuple):
            # We don't abbreviate pairs unless they are very large
            return False
        if ts <= 1:
            return False
        if ts > 5:
            return True
        if len(str(term)) > MAXTERMSIZE:
            return True
        if (len(str(term)) > 6) and (self.subtermcount[str(term)] > 2):
            return True
        return False

    def valCandidate(self,term):
        """
        Higher is more likely to be abbreviated.
        Currently lexicographic-ish (occurrences, size)
        """
        occ = self.subtermcount[str(term)]
        size = len(str(term))
        val = (occ**2) * size
        return val

    def select(self):

        self.bestval = None
        self.bestterm = None
        for term in self.subterms:
            if self.isCandidate(term):
                val = self.valCandidate(term)
                if (self.bestterm == None) or (val > self.bestval):
                    self.bestterm = term
                    self.bestval = max(self.bestval,val)

        return (self.bestterm,self.bestval)

    def newName(self):
        """
        Come up with a new name
        """

        pref = "M"
        cnt = 1
        
        substrings = [str(t) for t in self.subterms]
        substrings += self.abbreviations.keys()

        while ("%s%i" % (pref,cnt)) in substrings:
            cnt += 1

        return "%s%i" % (pref,cnt)


