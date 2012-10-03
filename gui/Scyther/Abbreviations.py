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
#MAXTERMSIZE = 16 # Hardcoded constant (makes sense for ASCII matrices)
MAXTERMSIZE = 30 # Hardcoded constant (makes sense for graphviz graphs)
MAXREPLACE = 7  # Not more than 7 replacements

import Term

class AbbrevContext(object):
    """
    Used to compute a single abbreviation that helps the most
    """

    def __init__(self,abbreviations={}):

        self.abbreviations = abbreviations
        self.trace = None
        self.termlist = None

    def abbreviate(self,termlist,replacefunc):
        """
        Return false if we ran out of options
        """
        self.termlist = termlist

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

        ab = self.select()
        if ab == None:
            return False

        nn = self.newName()
        abbrev = {}
        abbrev[str(ab)] = Term.TermConstant(nn)
        # Replace propagation
        replacefunc(abbrev)
        # Replace our own terms
        for k in self.abbreviations.keys():
            self.abbreviations[k] = self.abbreviations[k].replace(abbrev)
        self.abbreviations[nn] = ab

        return True

    def abbreviateAll(self,trace,tlfunc,replacefunc):
        """
        Repeatedly replace best candidate
        """
        global MAXREPLACE

        self.trace = trace
        while len(self.abbreviations.keys()) < MAXREPLACE:
            termlist = tlfunc()
            flag = self.abbreviate(termlist,replacefunc)
            if flag == False:
                break

        return self.abbreviations

    def isCandidate(self,term):
        """
        True iff we might be abbreviated
        """
        global MAXTERMSIZE

        ts = term.size()
        if term.getKeyAgents() != None:
            # We don't abbreviate keys, ever
            return False
        if (ts < 16) and isinstance(term.real(),Term.TermTuple):
            # We don't abbreviate pairs unless they are very large
            return False
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
        val = (1000 * occ) + size
        return val

    def select(self):

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


