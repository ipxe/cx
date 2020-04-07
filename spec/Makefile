DEPS = cx.bib

all : cx.pdf

%.pdf : %.lyx $(DEPS) Makefile
	lyx -e pdf2 $<

clean :
	$(RM) *.pdf
