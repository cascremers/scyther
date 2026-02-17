# There are two main targets:
#
#  scyther-manual.pdf
#		Produced the version of the manual that is immediately copied to its
#		target destination in ../gui; this is the static copy we want in the
#		repository anyway.
#
#  scyther-manual-draft.pdf
#		This is more of a development output, which also shows personal todo
#		notes. It enables the `draftversion` setting in the latex build.
#
all:	scyther-manual.pdf scyther-manual-draft.pdf

scyther-manual.pdf:	scyther-manual.tex biblio.bib 
	pdflatex scyther-manual.tex
	makeindex scyther-manual
	bibtex scyther-manual
	pdflatex scyther-manual.tex
	pdflatex scyther-manual.tex
	cp scyther-manual.pdf ../gui/

SDRAFT= --jobname=scyther-manual-draft "\def\draftversion{yes}\input{scyther-manual}"
scyther-manual-draft.pdf:	scyther-manual.tex biblio.bib
	pdflatex $(SDRAFT)
	makeindex scyther-manual
	bibtex scyther-manual
	pdflatex $(SDRAFT)
	pdflatex $(SDRAFT)


clean:
	\rm -f *.aux
	\rm -f *.log
	\rm -f *.bbl
	\rm -f *.blg
	\rm -f *.ind

realclean:	clean
	\rm -f scyther-manual-draft.pdf
	\rm -f scyther-manual.pdf




