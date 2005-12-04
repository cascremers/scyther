#!/usr/bin/python

import If
import Ifparser
import Spdl

def main():
	protocol = Ifparser.fileParse("NSPK_LOWE.if")
	print Spdl.generator(protocol)

if __name__ == "__main__":
	main()
