@VALGRIND_CHECK_RULES@

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -W -Wall -Wextra -Werror

lib_LTLIBRARIES = libcx.la
check_PROGRAMS = cxtest
TESTS = cxtest

libcx_la_SOURCES = drbg.c generator.c
libcx_la_CPPFLAGS = $(SSL_CFLAGS) $(AM_CPPFLAGS)

cxtest_SOURCES = cxtest.c gentest.c
cxtest_CPPFLAGS = $(SSL_CFLAGS) $(AM_CPPFLAGS)
cxtest_CFLAGS = $(AM_CFLAGS) -Wunused-const-variable=2
cxtest_LDADD = libcx.la $(SSL_LIBS)
