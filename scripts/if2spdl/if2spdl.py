#!/usr/bin/python

from parser import *
import pprint

def main():
	file = open("NSPK_LOWE.if", "r")
	res = ifParse ("".join(file.readlines() ) )
	pprint.pprint (res.asList())



if __name__ == "__main__":
	main()
