# Main target:
#
#  scyther-manual.pdf
#		Produces the manual PDF and copies it to ../gui/ for distribution
#
all:	scyther-manual.pdf

scyther-manual.pdf:	scyther-manual.tex biblio.bib 
	./get-version.sh
	pdflatex scyther-manual.tex
	makeindex scyther-manual
	bibtex scyther-manual
	pdflatex scyther-manual.tex
	pdflatex scyther-manual.tex
	cp scyther-manual.pdf ../gui/


clean:
	\rm -f *.aux
	\rm -f *.log
	\rm -f *.bbl
	\rm -f *.blg
	\rm -f *.ind
	\rm -f version.tex

realclean:	clean
	\rm -f scyther-manual.pdf




