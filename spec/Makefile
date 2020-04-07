DEPS = cx.bib
CFLAGS = -W -Wall -Wextra -Werror -Wno-unused-parameter

all : test doc

test : gen_sample.o gen_test
	./gen_test

doc : cx.pdf

%.pdf : %.lyx $(DEPS) Makefile
	lyx -e pdf2 $<

%.o : %.c
	$(CC) $(CFLAGS) -o $@ -c $<

gen_test : gen_test.c gen_sample.c
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto

clean :
	$(RM) *.pdf *.o
