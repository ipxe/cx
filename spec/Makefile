GEN_DEPS = gen_sample.c \
	   gen_type1_test1.c gen_type1_test2.c \
	   gen_type2_test1.c gen_type2_test2.c

SEEDCALC_DEPS = seedcalc_sample.c \
		seedcalc_type1_test1.c seedcalc_type1_test2.c \
		seedcalc_type1_test3.c \
		seedcalc_type2_test1.c seedcalc_type2_test2.c \
		seedcalc_type2_test3.c \
		ipxe.pubkey.c fensystems.pubkey.c

DEPS = cx.bib $(GEN_DEPS) $(SEEDCALC_DEPS)

CFLAGS = -W -Wall -Wextra -Werror -Wno-unused-parameter

all : test doc

test : gen_sample.o gen_test seedcalc_sample.o seedcalc_test
	./gen_test
	./seedcalc_test

doc : cx.pdf

version.tex :
	/bin/echo '\newcommand{\cxVersion}{$(VERSION)}' > $@

%.pdf : %.lyx version.tex $(DEPS) Makefile
	lyx -e pdf2 $<

%.o : %.c
	$(CC) $(CFLAGS) -o $@ -c $<

%.pubkey.der : %.pubkey.pem
	openssl rsa -pubin -in $< -outform DER -out $@

%.c : %.der
	xxd -i $< > $@

gen_test : gen_test.c $(GEN_DEPS)
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto

seedcalc_test : seedcalc_test.c $(SEEDCALC_DEPS)
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto

clean :
	$(RM) *.pdf *.o *.der *.pubkey.c gen_test seedcalc_test
	/bin/echo '\newcommand{\cxVersion}{}' > version.tex

.PHONY : version.tex
