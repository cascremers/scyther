#!/usr/bin/python
"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2008 Cas Cremers

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
# test.py
# experimenting with the constraint solver
#
# Ubuntu package: python-constraint
#
# http://labix.org/python-constraint
#

#---------------------------------------------------------------------------

""" Import externals """
import sys
try:
    from constraint import *
except:
    print "Could not import constraint solver module."
    print "For more information, visit"
    print "  http://labix.org/python-constraint"
    sys.exit()

#---------------------------------------------------------------------------

def test():
    problem = Problem()
    problem.addVariables(range(0, 16), range(1, 16+1))
    problem.addConstraint(AllDifferentConstraint(), range(0, 16))
    problem.addConstraint(ExactSumConstraint(34), [0,5,10,15])
    problem.addConstraint(ExactSumConstraint(34), [3,6,9,12])
    for row in range(4):
        problem.addConstraint(ExactSumConstraint(34),
                              [row*4+i for i in range(4)])
    for col in range(4):
        problem.addConstraint(ExactSumConstraint(34),
                              [col+4*i for i in range(4)])
    solutions = problem.getSolutions()
    print solutions

#---------------------------------------------------------------------------

if __name__ == '__main__':
    test()

