# Tuple module
#
# tuplesDo generates all unordered sets (in a list) of size n of the
# elements of the list l. The resulting lists (of length n) are passed
# to the function f.


# First some generic combinatorial stuff

def faculty_gen(n,k):
	if n <= k:
		return 1
	else:
		return n * faculty_gen(n-1,k)

def faculty(n):
	return faculty_gen(n,1)

def binomial(n,k):
	b1 = faculty_gen(n,k)
	b2 = faculty(n-k)
	return b1/b2


# How many elements will there be?
def tuples_count (l,n):
	return binomial(l,n)

# Generate those elements, and apply f
def tuples_do (f,l,n):
	def recurse (l,r):
		if r and (len(r) == n):
			f(r)
		else:
			if l and (n > 0):
				# Larger size: we have options
				# Option 1: include first
				recurse (l[1:], r + [l[0]])
				# Option 2: exclude first
				recurse (l[1:], r)

	recurse (l,[])


