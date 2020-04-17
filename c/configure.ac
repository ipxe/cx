# Configure autoconf
AC_INIT([libcx], [0.1], [mcb30@ipxe.org])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([src/generator.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

# Check for programs
AC_PROG_CC
AC_PROG_CXX
AM_PROG_AR

# Configure libtool
LT_INIT([shared])

# Configure automake
AM_INIT_AUTOMAKE([foreign subdir-objects])

# Check for libraries
PKG_CHECK_MODULES(SSL, openssl)

# Check for headers
AC_CHECK_HEADERS([stddef.h stdlib.h string.h \
		  openssl/rand_drbg.h openssl/x509.h])

# Check for types
AC_TYPE_SIZE_T

# Check for library functions
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

# Configure tests
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_CHECK
AM_EXTRA_RECURSIVE_TARGETS([check-valgrind])
m4_foreach([vgtool], [valgrind_tool_list],
	   [AM_EXTRA_RECURSIVE_TARGETS([check-valgrind-]vgtool)])

# Generate files
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
