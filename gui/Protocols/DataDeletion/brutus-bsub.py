#!/usr/bin/python

"""
Version of script that immediately invokes bsub 
without the generated scripts route
"""

import os
from subprocess import Popen,PIPE


def bsubJob(args=[],inputstring=None,script=None):
	"""
	<args> is the argument string list for bsub
	<script> is a script (file)name to be provided to stdin of bsub 
	<inputstring> is a string to be provided to stdin of bsub
	If both <script> and <inputstring> are defined (!= None) then first the
	<script> script is provided, and then the <inputstring>
	"""

	# Add e-mail notifications
	args = ["-B","-N","-u cas.cremers@inf.ethz.ch"] + args

	p = Popen(["bsub"] + args, stdin=PIPE)

	if script:
		fp = open(script,'r')
		for x in fp.xreadlines():
			p.communicate(x)
		fp.close()
	
	if inputstring:
		p.communicate(inputstring)

	p.stdin.close()
	p.wait()

def scytherJob(filename,runs,basename):

	#home = os.environ["HOME"]
	#scyther = "%s/bin/scyther-linux" % (home)
	scyther = "../../Scyther/scyther-linux"
	args = ["--partner-definition=2","--LKRothers=1","--LKRactor=1","--LKRafter=1","--SKR=1","--SSR=1"]
	args += ["--max-runs=%i" % (runs)]
	args += [filename]

	logname = "lsf-%s.log" % (basename)
	bsubJob(args=["-oo",logname,"-J",basename,"-W","23:00"],inputstring=(" ".join([scyther]+args)))

	
def makeAll():
	files = [('dd1-tag-simsig', 'dataDeletion1-tagged-simsig.spdl'), \
                 ('dd1-tag',	 'dataDeletion1-tagged.spdl'), \
                 ('dd1-tag-simp','dataDeletion1-tagged-simplified.spdl'), \
                 ('dd2-tag',     'dataDeletion2-tagged.spdl') ]
	files = [('sp1', 'ScytherProtocol1.spdl'), \
		 ('sp2', 'ScytherProtocol2.spdl')]
	files = [('sp1', 'ScytherProtocol1.spdl')]
	
	for (logid,filename) in files:
		for runs in range(2,10):
			basename = "%s-r%i" % (logid,runs)
			scytherJob(filename,runs,basename)

			

def main():
	makeAll()

if __name__ == '__main__':
	main()



