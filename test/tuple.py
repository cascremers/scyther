# Tuple module
#
# tuplesDo generates all unordered sets (in a list) of size n of the
# elements of the list l. The resulting lists (of length n) are passed
# to the function f.

def tuplesDo (f,l,n):
	def tuplesDoRecurse (l,r):
		if r and (len(r) == n):
			f(r)
		else:
			if l and (n > 0):
				# Larger size: we have options
				# Option 1: include first
				tuplesDoRecurse (l[1:], r + [l[0]])
				# Option 2: exclude first
				tuplesDoRecurse (l[1:], r)

	tuplesDoRecurse (l,[])


