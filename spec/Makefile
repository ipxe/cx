DEPS = cx.bib

all : test doc

test : gen_sample.o

doc : cx.pdf

%.pdf : %.lyx $(DEPS) Makefile
	lyx -e pdf2 $<

%.o : %.c
	$(CC) -W -Wall -Wextra -Werror -Wno-unused -o $@ -c $<

clean :
	$(RM) *.pdf *.o
