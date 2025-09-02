AC_INIT([eos-factory-tools], [0.0])

AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([factory-test])

AM_PROG_CC_C_O
PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([UDISKS], [udisks2])

AC_ARG_ENABLE([systemd],
	[systemd integration],
	enable_systemd=$enableval, enable_systemd=no)
AM_CONDITIONAL(ENABLE_SYSTEMD, [test "$enable_systemd" = yes])

AC_ARG_WITH([terminal],
            [AS_HELP_STRING([--with-terminal],
                            [Terminal application going to be launched])],
            [TERMINAL="$withval"],
            [TERMINAL="kgx"])
AC_SUBST(TERMINAL)

AC_ARG_WITH([terminal-parameters],
            [AS_HELP_STRING([--with-terminal-parameters],
                            [Pass parameters to terminal application])],
            [TERMINAL_PARAM="$withval"],
            [TERMINAL_PARAM="--title \"Endless OS Factory Test\" --wait"])
AC_SUBST(TERMINAL_PARAM)

AC_CONFIG_FILES([
	Makefile
	factory-test/Makefile
	factory-test/eos-factory-test.service
	mfgdata/Makefile])
AC_OUTPUT
