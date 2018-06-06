#!/usr/bin/make -f

# Project name.
package = $(shell grep ^Name: *.spec | awk '{print $$2}')

# Project version.
version = $(shell grep ^Version: *.spec | awk '{print $$2}')

# Where to put build products;
objdir = build/

# Current architecture;
arch = $(shell uname -m)

CC = gcc -fdiagnostics-color=auto
CXX = g++ -fdiagnostics-color=auto
cc = ${CC}
cxx = ${CXX}

cppflags = -Wall -W -Werror -Wno-unused-parameter\
	   -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
	   -Iinclude -DVERSION='"${version}"' -DPACKAGE='"${package}"' \
	   -D_FORTIFY_SOURCE=2 ${CPPFLAGS}
cflags = -std=gnu11 -fPIC -O2 -g ${CFLAGS}
cxxflags = -fPIC -O2 -g -fexceptions ${CXXFLAGS}
ldflags = -Wl,--warn-shared-textrel,--fatal-warnings ${LDFLAGS}

valgrind = valgrind -q --tool=memcheck

ifneq ($(wildcard arch/${arch}.mk),)
 $(info Loading arch/${arch}.mk)
 include arch/${arch}.mk
endif

lib64 = $(shell if uname -m | grep -q 64; then echo lib64; else echo lib; fi)

prefix = /usr
bindir = ${prefix}/bin
sbindir = ${prefix}/sbin
libdir = ${prefix}/${lib64}
includedir = ${prefix}/include
datadir = ${prefix}/share
pkgdatadir = ${datadir}/${package}

include $(wildcard deps/*.mk)
-include local.mk

# EOF
