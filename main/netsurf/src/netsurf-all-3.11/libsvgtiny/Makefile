#!/bin/make
#
# Makefile for libsvgtiny
#
# Copyright 2009-2015 John-Mark Bell <jmb@netsurf-browser.org>

# Component settings
COMPONENT := svgtiny
COMPONENT_VERSION := 0.1.8
# Default to a static library
COMPONENT_TYPE ?= lib-static

# Setup the tooling
PREFIX ?= /opt/netsurf
NSSHARED ?= $(PREFIX)/share/netsurf-buildsystem
include $(NSSHARED)/makefiles/Makefile.tools

# Reevaluate when used, as BUILDDIR won't be defined yet
TESTRUNNER = test/runtest.sh $(BUILDDIR) $(EXEEXT)

# Toolchain flags
WARNFLAGS := -Wall -W -Wundef -Wpointer-arith -Wcast-align \
	-Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes \
	-Wmissing-declarations -Wnested-externs -pedantic
# BeOS/Haiku/AmigaOS standard library headers create warnings
ifneq ($(BUILD),i586-pc-haiku)
  ifneq ($(findstring amigaos,$(BUILD)),amigaos)
    WARNFLAGS := $(WARNFLAGS) 
  endif
endif

CFLAGS := -D_BSD_SOURCE -D_DEFAULT_SOURCE \
	-I$(CURDIR)/include/ -I$(CURDIR)/src \
	$(WARNFLAGS) $(CFLAGS)
ifneq ($(GCCVER),2)
  CFLAGS := $(CFLAGS) -std=c99
else
  # __inline__ is a GCCism
  CFLAGS := $(CFLAGS) -Dinline="__inline__"
endif

# libdom
ifneq ($(PKGCONFIG),)
  CFLAGS := $(CFLAGS) \
		$(shell $(PKGCONFIG) $(PKGCONFIGFLAGS) --cflags libdom libwapcaplet)
  LDFLAGS := $(LDFLAGS) -lm \
		$(shell $(PKGCONFIG) $(PKGCONFIGFLAGS) --libs libdom libwapcaplet)
else
  CFLAGS := $(CFLAGS) -I$(PREFIX)/include
  LDFLAGS := $(CFLAGS) -ldom -lwapcaplet -lexpat -lm
endif

include $(NSBUILD)/Makefile.top

# Extra installation rules
I := /$(INCLUDEDIR)
INSTALL_ITEMS := $(INSTALL_ITEMS) $(I):include/svgtiny.h
INSTALL_ITEMS := $(INSTALL_ITEMS) /$(LIBDIR)/pkgconfig:lib$(COMPONENT).pc.in
INSTALL_ITEMS := $(INSTALL_ITEMS) /$(LIBDIR):$(OUTPUT)
