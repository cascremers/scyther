#!/usr/bin/python
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

"""
    This program generates arbitrary members of the ffgg protocol family, as proposed
    by Jonathan Millen in the paper "A Necessarily Parallel Attack".
    By providing a number n as the input, the program outputs on stdout the
    corresponding protocol ffgg_n.
"""

import sys

def nlist(pref,post,si,ei):
    s = ""
    for x in range(si,ei+1):
        if s != "":
            s += ","
        s += "%s%i" % (pref,x)
        s += post
    return s

def ffgg(n):
    s = """

/* 
 * ffgg%i protocol
 */

// The protocol description

protocol ffgg%i(A,B)
{
	role A
	{
        """ % (n,n)

    nonces1 = nlist("n","",1,n)
    nonces1b = nlist("n","",2,n)
    nonces2 = nlist("n","b",2,n)
    ivar = nonces1
    rvar = nonces2
    rconst = nonces1

    s += """
		fresh M: Nonce;
		var %s: Nonce;

		send_1(A,B, A );
		read_2(B,A, B,%s );
		send_3(A,B, A,{%s,M}pk(B) );
		read_4(B,A, n1,n2,{%s,M,n1}pk(B) );

		claim_i1(A,Secret,M);
	}	
	
	role B
	{
		var M,%s: Nonce;
		fresh %s: Nonce;

		read_1(A,B, A );
		send_2(B,A, B,%s );
		read_3(A,B, A,{n1,%s,M}pk(B) );
		send_4(B,A, n1,n2b,{%s,M,n1}pk(B) );
	}
}

    """ % (ivar,nonces1,nonces1,nonces1b,rvar,rconst,nonces1,nonces2,nonces2)

    return s

if __name__ == '__main__':
    if len(sys.argv) > 1:
        print ffgg(int(sys.argv[1]))
    else:
        print "Please provide a number n to generate ffgg_n"

