GEN_DEPS = gen_sample.c \
	   gen_type1_test1.c gen_type1_test2.c \
	   gen_type2_test1.c gen_type2_test2.c

SEEDCALC_DEPS = seedcalc_sample.c \
		seedcalc_type1_test1.c seedcalc_type1_test2.c \
		seedcalc_type1_test3.c \
		seedcalc_type2_test1.c seedcalc_type2_test2.c \
		seedcalc_type2_test3.c \
		ipxe.pubkey.c fensystems.pubkey.c

ASN1_FRAGS = cx-generatortype.asn1 cx-seedreportversion.asn1 \
	     cx-preseedvalue-preseedvalues.asn1 cx-tbsseedreport.asn1 \
	     cx-seedreport.asn1

DEPS = cx.bib $(GEN_DEPS) $(SEEDCALC_DEPS)

CFLAGS = -W -Wall -Wextra -Werror -Wno-unused-parameter

all : test doc

test : test-samples test-asn1

doc : cx.pdf

version.tex :
	/bin/echo '\newcommand{\cxVersion}{$(VERSION)}' > $@

%.pdf : %.lyx version.tex $(DEPS) Makefile
	lyx -e pdf2 $<

test-samples : gen_sample.o gen_test seedcalc_sample.o seedcalc_test
	./gen_test
	./seedcalc_test

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

test-asn1 : $(patsubst %,%.check,$(ASN1_FRAGS))
	asn1c -EF cx.asn1 rfc5280.asn1 > /dev/null

cx-%.asn1.check : cx.asn1
	sed -E -n '/^($(subst -,|,$*)) ::=/I,/^$$/p' $< | diff $(basename $@) -

cx-%.asn1 : cx.asn1
	sed -E -n '/^($(subst -,|,$*)) ::=/I,/^$$/p' $< > $@

.PRECIOUS : cx-%.asn1

clean :
	$(RM) *.pdf *.o *.der *.pubkey.c gen_test seedcalc_test
	/bin/echo '\newcommand{\cxVersion}{}' > version.tex

.PHONY : version.tex
