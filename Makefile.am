
lib_LTLIBRARIES = libsha1.la
libsha1_la_SOURCES = sha1.c

include_HEADERS = libsha1.h

noinst_PROGRAMS = test
test_LDADD = libsha1.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsha1.pc

EXTRA_DIST = libsha1.pc.in
