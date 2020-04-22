@VALGRIND_CHECK_RULES@

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -W -Wall -Wextra -Werror

lib_LTLIBRARIES = libcx.la
check_PROGRAMS = cxtest
TESTS = cxtest

libcx_la_SOURCES = debug.h drbg.c generator.c seedcalc.c preseed.c
libcx_la_CPPFLAGS = $(SSL_CFLAGS) $(AM_CPPFLAGS)
libcx_la_LIBADD = $(SSL_LIBS)

PUBKEY_SOURCES = tests/key_a.c tests/key_b.c
PUBKEY_PEM = $(patsubst %.c,%.pem,$(PUBKEY_SOURCES))

TEST_SOURCES = tests/gen_type1_test1.c \
	       tests/gen_type1_test2.c \
	       tests/gen_type2_test1.c \
	       tests/gen_type2_test2.c \
	       tests/seedcalc_type1_test1.c \
	       tests/seedcalc_type1_test2.c \
	       tests/seedcalc_type1_test3.c \
	       tests/seedcalc_type2_test1.c \
	       tests/seedcalc_type2_test2.c \
	       tests/seedcalc_type2_test3.c \
	       $(PUBKEY_SOURCES)

cxtest_SOURCES = cxtest.h cxtest.c \
		 gentest.h gentest.c \
		 seedcalctest.h seedcalctest.c \
		 preseedtest.h preseedtest.c \
		 $(TEST_SOURCES)
cxtest_CPPFLAGS = $(SSL_CFLAGS) -include cxtest.h $(AM_CPPFLAGS)
cxtest_CFLAGS = $(AM_CFLAGS) -Wunused-const-variable=2
cxtest_LDADD = libcx.la $(SSL_LIBS)

EXTRA_DIST = linktest.c $(PUBKEY_PEM)

$(srcdir)/tests/key_%.der : $(srcdir)/tests/key_%.pem
	openssl rsa -pubin -in $< -outform DER -out $@

$(srcdir)/tests/key_%.c : $(srcdir)/tests/key_%.der
	( cd $(dir $<) && xxd -i $(notdir $<) ) > $@

mostlyclean-local:
	$(RM) tests/*.der

maintainer-clean-local:
	$(RM) tests/key_*.c
