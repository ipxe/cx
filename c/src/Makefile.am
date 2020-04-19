@VALGRIND_CHECK_RULES@

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -W -Wall -Wextra -Werror

lib_LTLIBRARIES = libcx.la
check_PROGRAMS = cxtest
TESTS = cxtest

libcx_la_SOURCES = debug.h drbg.c generator.c seedcalc.c preseed.c
libcx_la_CPPFLAGS = $(SSL_CFLAGS) $(AM_CPPFLAGS)
libcx_la_LIBADD = $(SSL_LIBS)

cxtest_SOURCES = cxtest.c \
		 gentest.h gentest.c \
		 seedcalctest.h seedcalctest.c \
		 preseedtest.h preseedtest.c
cxtest_CPPFLAGS = $(SSL_CFLAGS) $(AM_CPPFLAGS)
cxtest_CFLAGS = $(AM_CFLAGS) -Wunused-const-variable=2
cxtest_LDADD = libcx.la $(SSL_LIBS)

EXTRA_DIST = linktest.c

PUBKEY_PEM = tests/key_a.pem tests/key_b.pem
PUBKEY_DER = $(patsubst %.pem,%.der,$(PUBKEY_PEM))
PUBKEY_C = $(patsubst %.pem,%.c,$(PUBKEY_PEM))
BUILT_SOURCES = $(PUBKEY_C)
CLEANFILES = $(PUBKEY_C) $(PUBKEY_DER)

tests/key_%.der : tests/key_%.pem Makefile
	openssl rsa -pubin -in $< -outform DER -out $@

tests/key_%.c : tests/key_%.der Makefile
	( cd $(dir $<) && xxd -i $(notdir $<) ) > $@
