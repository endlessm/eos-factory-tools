AC_INIT([eos-factory-tools], [0.0])

AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([factory-test])

AM_PROG_CC_C_O
PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([UDISKS], [udisks2])

AC_ARG_ENABLE([systemd],
	[systemd integration],
	enable_systemd=$enableval,
	enable_systemd=yes)
AM_CONDITIONAL(ENABLE_SYSTEMD, [test "$enable_systemd" = yes])

AC_CONFIG_FILES([
	Makefile
	factory-test/Makefile
	mfgdata/Makefile])
AC_OUTPUT
