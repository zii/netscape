# -*- Mode: Makefile -*-
#
# The contents of this file are subject to the Netscape Public License
# Version 1.0 (the "NPL"); you may not use this file except in
# compliance with the NPL.  You may obtain a copy of the NPL at
# http://www.mozilla.org/NPL/
#
# Software distributed under the NPL is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
# for the specific language governing rights and limitations under the
# NPL.
#
# The Initial Developer of this code under the NPL is Netscape
# Communications Corporation.  Portions created by Netscape are
# Copyright (C) 1998 Netscape Communications Corporation.  All Rights
# Reserved.
#

DEPTH		= ..

HSRCS		= pathsub.h
CSRCS		= nsinstall.c pathsub.c

ifeq ($(subst /,_,$(shell uname -s)),OS2)
DIRS		= os2
LOCAL_INCLUDES	+= -Ios2
HSRCS		+= dirent.h getopt.h
endif

PLSRCS		= nfspwd.pl revdepth.pl

TARGETS		= $(PROGRAM) $(PLSRCS:.pl=)

# Generate the build number on the fly.
TARGETS		+= $(DEPTH)/build/build_number

ifneq ($(subst /,_,$(shell uname -s)),WINNT)
PROGRAM		= nsinstall$(BIN_SUFFIX)
TARGETS		+= $(OBJDIR)/bsdecho$(BIN_SUFFIX)
endif

# IMPORTANT: Disable NSBUILDROOT for this directory only, otherwise we have
# a recursive rule for finding nsinstall and the perl scripts
ifdef NSBUILDROOT
override NSBUILDROOT :=
endif

include $(DEPTH)/config/rules.mk

ifeq ($(OS_ARCH)$(OS_RELEASE),SunOS4.1)
INCLUDES	+= -I../nsprpub/pr/include/md
endif

ifeq ($(OS_ARCH)$(OS_RELEASE),IRIX5)
TARGETS		+= $(OBJDIR)/gtscc$(BIN_SUFFIX)
endif

# Redefine MAKE_OBJDIR for just this directory
define MAKE_OBJDIR
if test ! -d $(@D); then rm -rf $(@D); mkdir $(@D); fi
endef

export:: $(TARGETS)

ifeq ($(OS_ARCH),OS2)
# could not get bsdecho rules to work implicitly, so here is explicit ones
$(OBJDIR)/bsdecho.o:  bsdecho.c
	@$(MAKE_OBJDIR)
	$(CC) -Fo$@ $(CFLAGS) -c $<

$(OBJDIR)/bsdecho$(BIN_SUFFIX):	$(OBJDIR)/bsdecho.o
	@$(MAKE_OBJDIR)
	$(LINK_EXE) -OUT:$@ $< $(LDFLAGS)
	$(INSTALL) -m 444 $@ $(DIST)/bin
else
$(OBJDIR)/bsdecho$(BIN_SUFFIX):	$(OBJDIR)/bsdecho.o
	@$(MAKE_OBJDIR)
	$(CCF) $(LDFLAGS) -o $@ $<
	$(INSTALL) -m 444 $@ $(DIST)/bin
endif

$(OBJDIR)/gtscc$(BIN_SUFFIX):	$(OBJDIR)/gtscc.o
	@$(MAKE_OBJDIR)
	$(CCF) $(LDFLAGS) -o $@ $< -lelf
	$(INSTALL) -m 444 $@ $(DIST)/bin

#update build number from within make script
$(DEPTH)/build/build_number: $(OBJDIR)/bdate$(BIN_SUFFIX) FORCE
	$(RM) $@
	$(OBJDIR)/bdate$(BIN_SUFFIX) > $@

$(OBJDIR)/bdate$(BIN_SUFFIX): $(OBJDIR)/bdate.o
	@$(MAKE_OBJDIR)
	$(CCF) $(LDFLAGS) -o $@ $<
	$(INSTALL) -m 444 $@ $(DIST)/bin

FORCE:

ifdef MKDEPEND_DIR
clean clobber realclean clobber_all::
	cd $(MKDEPEND_DIR); $(MAKE) $@
endif

ifdef MOZILLA_DETECT
clean clobber realclean clobber_all::
	cd $(MOZILLA_DETECT_DIR); $(MAKE) $@
endif

# For the continuous build scripts.
show_objname:
	@echo $(OBJDIR)

.PHONY: show_objname
