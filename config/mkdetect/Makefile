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

DEPTH		= ../..

# A uniq identifier that describes this host
DETECT_UNIQ_IDENT = $(shell $(DETECT_DIR)/detect_hostident.sh)

# Where we live
DETECT_DIR	= $(DEPTH)/config/mkdetect

# Name of genereated makefile
DETECT_NAME	= detect_$(DETECT_UNIQ_IDENT)_gen.mk

# The glibc detection script
DETECT_GLIBC	= $(DETECT_DIR)/detect_glibc.sh -o $(DETECT_UNIQ_IDENT)

# The motif detection script
DETECT_MOTIF	=\
				$(DETECT_DIR)/detect_motif.sh -o $(DETECT_UNIQ_IDENT) \
				-xif $(X11_INCLUDE_FLAGS)

# The X11 detection script
DETECT_X11	= $(DETECT_DIR)/detect_x11.sh -o $(DETECT_UNIQ_IDENT)

# The following macros are generated:
#
# MOZILLA_XFE_GLIBC_BROKEN_LOCALE_FLAGS
#	Needed because of currently broken locale support when mixing gnu
#	libc2 with any version of motif.
#
#
# MOZILLA_XFE_MOTIF_PRINT_SHELL_FLAGS
#	X Print Shell Extension (available starting with X11R6.3) needed
#	by motif 2.1.
#
#
# MOZILLA_XFE_USE_WINNING_FILE_SELECTION
#	Hacks to the motif file selection code to "fix" it.  Where "fix" 
#	means "make the motif fsb not suck as hell".  Motif source code
#	is needed for this hack (it breaks with lesstif)
#
#
# Questions about any of these flags or this wacky scheme in general, should 
# go to ramiro@netscape.com.
#

all: export

export: $(DETECT_NAME)
detect: $(DETECT_NAME)

clean:
	@rm -f $(DETECT_NAME)
	@$(DETECT_X11) --cleanup 
	@$(DETECT_MOTIF) --cleanup 
	@$(DETECT_GLIBC) --cleanup

clobber: clean
realclean: clean

# This is needed for DETECT_MOTIF to work
X11_INCLUDE_FLAGS=$(shell $(DETECT_X11) -if)

$(DETECT_NAME):
	@echo "Generating $(DETECT_NAME)."
	@rm -f $@
	@touch $@
	@echo "#" >> $@
	@echo "# Do Not edit." >> $@
	@echo "# Automagically generated file." >> $@
	@echo "#" >> $@
	@echo >> $@
	@echo >> $@

##
## GLIBC
##

##
## In theory, you can use glibc2 in many platforms.  Right now only Linux
## seems to be using it, though.
##
## Test whether -lBrokenLocale is needed.  Locale support is broken
## when using motif (any version) with gnu libc2.  
##
ifeq ($(shell $(DETECT_GLIBC)),2)
	@echo "# GLIBC2" >> $@
	@echo "MOZILLA_XFE_USING_GLIBC2 = 1" >> $@
	@echo >> $@
	@echo "# Broken Locale" >> $@
	@echo "MOZILLA_XFE_GLIBC_BROKEN_LOCALE_FLAGS = -lBrokenLocale" >> $@
endif

##
## X11
##

##
## Set the x11 include flags
##
	@echo >> $@
	@echo "# X11" >> $@
	@echo "MOZILLA_XFE_X11_INCLUDE_FLAGS = `$(DETECT_X11) -if`" >> $@

##
## Determine if we have static x11 libs and set static flags.
##
ifneq ($(shell $(DETECT_X11) -sl),unknown)
	@echo "MOZILLA_XFE_X11_HAVE_STATIC_LIB = 1" >> $@
	@echo "MOZILLA_XFE_X11_STATIC_FLAGS = `$(DETECT_X11) -sf`" >> $@
endif

##
## Determine if we have dynamic x11 libs and set dynamic flags.
##
ifneq ($(shell $(DETECT_X11) -dl),unknown)
	@echo "MOZILLA_XFE_X11_HAVE_DYNAMIC_LIB = 1" >> $@
	@echo "MOZILLA_XFE_X11_DYNAMIC_PATHS = `$(DETECT_X11) -dp`" >> $@
	@echo "MOZILLA_XFE_X11_DYNAMIC_FLAGS = `$(DETECT_X11) -df`" >> $@
endif

##
## Test whether -lSM -lICE are needed.   These libs are need for session
## management in X11R6.
##
ifeq ($(shell $(DETECT_X11)),6)
	@echo "MOZILLA_XFE_X11_SM_FLAGS = -lSM -lICE" >> $@
endif

##
## Motif
##

##
## Set the motif include flags
##
	@echo >> $@
	@echo "# Motif" >> $@
	@echo "MOZILLA_XFE_MOTIF_INCLUDE_FLAGS = `$(DETECT_MOTIF) -if`" >> $@

##
## Determine if we have static motif libs and set static flags.
##
ifneq ($(shell $(DETECT_MOTIF) -sl),unknown)
	@echo "MOZILLA_XFE_MOTIF_HAVE_STATIC_LIB = 1" >> $@
	@echo "MOZILLA_XFE_MOTIF_STATIC_FLAGS = `$(DETECT_MOTIF) -sf`" >> $@
endif

##
## Determine if we have dynamic motif libs and set dynamic flags.
##
ifneq ($(shell $(DETECT_MOTIF) -dl),unknown)
	@echo "MOZILLA_XFE_MOTIF_HAVE_DYNAMIC_LIB = 1" >> $@
	@echo "MOZILLA_XFE_MOTIF_DYNAMIC_PATHS = `$(DETECT_MOTIF) -dp`" >> $@
	@echo "MOZILLA_XFE_MOTIF_DYNAMIC_FLAGS = `$(DETECT_MOTIF) -df`" >> $@
endif

##
## Test whether -lXp is needed.   The -lXp (Print Shell Extensions)
## are needed only with motif 2.1.
##
ifeq ($(shell $(DETECT_MOTIF)),2.1)
	@echo "MOZILLA_XFE_MOTIF_PRINT_SHELL_FLAGS = -lXp" >> $@
endif

##
## Test whether -lXpm is needed.   The -lXpm (X Pixmap Libary) is needed
## by some versions of motif.  Some vendors try to do their customers
## favours by hacking the stock motif libs to include Xpm support.
##
ifeq ($(shell $(DETECT_MOTIF) -xpm),True)
	@echo "MOZILLA_XFE_MOTIF_XPM_FLAGS = -lXpm" >> $@
endif

##
## Test whether we are using "real" motif libraries.  If we are, then
## we can turn on the file selection hack which only works with motif
## (not lesstif)
##
ifneq ($(shell $(DETECT_MOTIF) -l),True)
	@echo >> $@
	@echo "# Winning File Selection" >> $@
	@echo "MOZILLA_XFE_USE_WINNING_FILE_SELECTION = 1" >> $@
endif

##
## Lots of other magical things can be detected here.
##

