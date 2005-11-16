#!/usr/bin/python

from parser import *
from generator import *
import pprint

def main():
	file = open("NSPK_LOWE.if", "r")
	res = ifParse ("".join(file.readlines() ) )
	generateSpdl(res)
	#pprint.pprint (res.asList())


if __name__ == "__main__":
	main()
