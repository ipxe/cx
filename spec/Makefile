DEPS = cx.bib

all : test doc

test : gen_sample.o gen_test
	./gen_test

doc : cx.pdf

%.pdf : %.lyx $(DEPS) Makefile
	lyx -e pdf2 $<

%.o : %.c
	$(CC) -W -Wall -Wextra -Werror -Wno-unused -o $@ -c $<

gen_test : gen_test.c gen_sample.c
	$(CC) -W -Wall -Wextra -Werror -Wno-unused -o $@ $< -lssl -lcrypto

clean :
	$(RM) *.pdf *.o
