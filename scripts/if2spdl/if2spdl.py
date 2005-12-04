#!/usr/bin/python

import If
import Ifparser
import Spdl

def main():
	file = open("NSPK_LOWE.if", "r")
	rulelist = Ifparser.linesParse(file.readlines())
	file.close()
	print Spdl.generator(rulelist)

if __name__ == "__main__":
	main()
