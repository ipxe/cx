AC_INIT([libcx], [0.1], [mcb30@ipxe.org])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([src/generator.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AM_PROG_AR
PKG_CHECK_MODULES(SSL, openssl)
AC_CHECK_HEADERS([stdlib.h openssl/rand_drbg.h openssl/x509.h])
AC_TYPE_SIZE_T
AC_CHECK_FUNCS([RAND_DRBG_instantiate])
LT_INIT([shared])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
