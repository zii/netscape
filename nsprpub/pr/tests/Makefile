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

#! gmake

MOD_DEPTH = ../..

include $(MOD_DEPTH)/config/config.mk

ifeq ($(OS_TARGET), WIN16)
OS_CFLAGS = $(OS_EXE_CFLAGS)
W16STDIO = $(MOD_DEPTH)/pr/src/md/windows/$(OBJDIR)/w16stdio.$(OBJ_SUFFIX)
endif

ifeq ($(OS_TARGET),WIN16)
DIRS = dll w16gui
else
DIRS = dll
endif

ifeq ($(OS_TARGET),OS2)
OS_CFLAGS = $(OS_EXE_CFLAGS)
endif

CSRCS =             \
	accept.c		\
	alarm.c			\
	atomic.c		\
	attach.c		\
	bigfile.c		\
	cleanup.c		\
	cltsrv.c		\
	concur.c	    \
	cvar.c			\
	cvar2.c			\
	dceemu.c		\
	dlltest.c		\
	dtoa.c			\
	exit.c  		\
	fileio.c		\
	forktest.c	    \
	fsync.c	        \
	getproto.c		\
	i2l.c		    \
	inrval.c		\
	intrupt.c       \
	io_timeout.c    \
	ipv6.c          \
	join.c    		\
	joinkk.c        \
	joinku.c        \
	joinuk.c        \
	joinuu.c        \
	layer.c		    \
	lazyinit.c		\
	lltest.c        \
	lock.c          \
	lockfile.c      \
	logger.c		\
	multiwait.c		\
	many_cv.c		\
	nbconn.c		\
	nblayer.c		\
	nonblock.c		\
	op_2long.c      \
	op_filnf.c		\
	op_filok.c		\
	op_noacc.c		\
	op_nofil.c		\
	parent.c    	\
	perf.c    		\
	poll_er.c		\
	poll_nm.c		\
	poll_to.c		\
	prftest1.c		\
	prftest2.c		\
	priotest.c		\
	ranfile.c       \
	sel_spd.c  		\
	selct_er.c	    \
	selct_nm.c	    \
	selct_to.c	    \
	select2.c  		\
	sem.c 	  		\
	servr_kk.c		\
	servr_ku.c		\
	servr_uk.c		\
	short_thread.c	\
	sigpipe.c		\
	socket.c		\
	sockopt.c		\
	sprintf.c		\
	sproc_ch.c	    \
	sproc_p.c	    \
	stdio.c		    \
	strod.c			\
	suspend.c		\
	switch.c		\
	system.c		\
	testbit.c    	\
	testfile.c    	\
	threads.c 	  	\
	thruput.c 	  	\
	timemac.c		\
	timetest.c		\
	tmoacc.c        \
	tmocon.c        \
	tpd.c			\
	udpsrv.c	    \
	writev.c        \
	xnotify.c       \
	$(NULL)

ifeq ($(OS_ARCH), WINNT)
PROG_SUFFIX = .exe
else
PROG_SUFFIX =
endif

PROGS = $(addprefix $(OBJDIR)/, $(CSRCS:.c=$(PROG_SUFFIX)))

TARGETS = $(PROGS) $(OBJS)

INCLUDES = -I$(DIST)/include/obsolete -I$(DIST)/include/private -I$(DIST)/include 

# Setting the variables LDOPTS and LIBPR.  We first initialize
# them to the default values, then adjust them for some platforms.
LDOPTS = -L$(DIST)/lib
LIBPR = -lnspr$(MOD_VERSION)
LIBPLC = -lplc$(MOD_VERSION)

ifeq ($(OS_ARCH), WINNT)
ifeq ($(OS_TARGET), WIN16)
  LIBPR = $(DIST)/lib/nspr$(MOD_VERSION).lib
  LIBPLC= $(DIST)/lib/plc$(MOD_VERSION).lib
else
ifeq ($(OS_TARGET), OS2)
  LDOPTS = -NOE -DEBUG -nologo -PMTYPE:VIO
  LIBPR = $(DIST)/lib/nspr$(MOD_VERSION).lib
  LIBPLC= $(DIST)/lib/plc$(MOD_VERSION).lib
else
  LDOPTS = -NOLOGO -DEBUG -DEBUGTYPE:CV -INCREMENTAL:NO
  LIBPR = $(DIST)/lib/libnspr$(MOD_VERSION).$(LIB_SUFFIX)
  LIBPLC= $(DIST)/lib/libplc$(MOD_VERSION).$(LIB_SUFFIX)
endif
endif
endif

ifneq ($(OS_ARCH), WINNT)
PWD = $(shell pwd)
endif

ifeq ($(OS_ARCH), IRIX)
LDOPTS += -rpath $(PWD)/$(DIST)/lib -rdata_shared

# For 6.x machines, include this flag
ifeq ($(basename $(OS_RELEASE)),6)
ifeq ($(USE_N32),1)
LDOPTS += -n32
else
LDOPTS += -32
endif
endif

endif

ifeq ($(OS_ARCH), OSF1)
# I haven't figured out how to pass -rpath to cc on OSF1 V3.2, so
# we do static linking.
ifeq ($(OS_RELEASE), V3.2)
  LIBPR = $(DIST)/lib/libnspr$(MOD_VERSION).a
  LIBPLC = $(DIST)/lib/libplc$(MOD_VERSION).a
  EXTRA_LIBS = -lc_r
else
  LDOPTS += -rpath $(PWD)/$(DIST)/lib
endif
endif

ifeq ($(OS_ARCH), HP-UX)
LDOPTS += -Wl,+s,+b,$(PWD)/$(DIST)/lib
endif

# AIX
ifeq ($(OS_ARCH),AIX)
ifeq ($(CLASSIC_NSPR),1)
LDOPTS += -blibpath:.:$(PWD)/$(DIST)/lib:/usr/lpp/xlC/lib:/usr/lib:/lib
else
LDOPTS += -blibpath:.:$(PWD)/$(DIST)/lib:/usr/lib/threads:/usr/lpp/xlC/lib:/usr/lib:/lib
endif
ifeq ($(OS_ARCH)$(OS_RELEASE),AIX4.1)
LIBPR = -lnspr$(MOD_VERSION)_shr
LIBPLC = -lplc$(MOD_VERSION)_shr
else
LDOPTS += -brtl
EXTRA_LIBS = -ldl
endif
endif

# Solaris
ifeq ($(OS_ARCH), SunOS)
ifneq ($(OS_RELEASE), 4.1.3_U1)
ifdef NS_USE_GCC
LDOPTS += -Xlinker -R -Xlinker $(PWD)/$(DIST)/lib
else
LDOPTS += -R $(PWD)/$(DIST)/lib
endif
endif

ifneq ($(LOCAL_THREADS_ONLY),1)
# SunOS 5.4 and 5.5 need to link with -lthread or -lpthread,
# even though we already linked with these system libraries
# when we built libnspr.so.
ifeq ($(OS_RELEASE), 5.4)
EXTRA_LIBS = -lthread
endif

ifeq ($(OS_RELEASE), 5.5)
ifdef USE_PTHREADS
EXTRA_LIBS = -lpthread
else
EXTRA_LIBS = -lthread
endif
endif
endif # LOCAL_THREADS_ONLY
endif # SunOS

ifeq ($(OS_ARCH), NEC)
EXTRA_LIBS = $(OS_LIBS)
# This hardcodes in the executable programs the directory to find
# libnspr.so etc. at program startup.  Equivalent to the -R or -rpath
# option for ld on other platforms.
export LD_RUN_PATH = $(PWD)/$(DIST)/lib
endif

ifeq ($(OS_ARCH), NCR)
# NCR needs to link against -lsocket -lnsl -ldl (and -lc, which is
# linked implicitly by $(CC)).  Note that we did not link with these
# system libraries when we built libnspr.so.
EXTRA_LIBS = -lsocket -lnsl -ldl
# This hardcodes in the executable programs the directory to find
# libnspr.so etc. at program startup.  Equivalent to the -R or -rpath 
# option for ld on other platforms.
export LD_RUN_PATH = $(PWD)/$(DIST)/lib
endif

ifeq ($(OS_ARCH), NEWS-OS)
# This hardcodes in the executable programs the directory to find
# libnspr.so etc. at program startup.  Equivalent to the -R or -rpath 
# option for ld on other platforms.
#export LD_RUN_PATH = $(PWD)/$(DIST)/lib
  LIBPR = $(DIST)/lib/libnspr$(MOD_VERSION).a
  LIBPLC = $(DIST)/lib/libplc$(MOD_VERSION).a
  EXTRA_LIBS = -lsocket -lnsl -lgen -lresolv
endif

ifeq ($(OS_ARCH), Linux)
ifeq ($(OS_RELEASE), 1.2)
EXTRA_LIBS = -ldl
else
LDOPTS += -Xlinker -rpath $(PWD)/$(DIST)/lib
ifeq ($(USE_PTHREADS),1)
EXTRA_LIBS = -lpthread
endif
endif
endif

ifeq ($(OS_ARCH), SCOOS)
# SCO Unix needs to link against -lsocket again even though we
# already linked with these system libraries when we built libnspr.so.
EXTRA_LIBS = -lsocket
# This hardcodes in the executable programs the directory to find
# libnspr.so etc. at program startup.  Equivalent to the -R or -rpath 
# option for ld on other platforms.
export LD_RUN_PATH = $(PWD)/$(DIST)/lib
endif

ifeq ($(OS_ARCH),SINIX)
EXTRA_LIBS = -lsocket -lnsl -lresolv -ldl
# This hardcodes in the executable programs the directory to find
# libnspr.so etc. at program startup.  Equivalent to the -R or -rpath
# option for ld on other platforms.
export LD_RUN_PATH = $(PWD)/$(DIST)/lib
endif

ifeq ($(OS_ARCH), UNIXWARE)
export LD_RUN_PATH = $(PWD)/$(DIST)/lib
endif

ifeq ($(OS_ARCH),FreeBSD)
ifeq ($(USE_PTHREADS),1)
EXTRA_LIBS = -lc_r
endif
endif

ifeq ($(OS_ARCH),BSD_OS)
EXTRA_LIBS = -ldl
endif

#####################################################
#
# The rules
#
#####################################################

include $(MOD_DEPTH)/config/rules.mk

AIX_PRE_4_2 = 0
ifeq ($(OS_ARCH),AIX)
ifeq ($(OS_RELEASE),4.1)
ifneq ($(USE_PTHREADS), 1)
#AIX_PRE_4_2 = 1
endif
endif
endif

ifeq ($(AIX_PRE_4_2),1)

# AIX releases prior to 4.2 need a special two-step linking hack
# in order to both override the system select() and be able to 
# get at the original system select().
#
# We use a pattern rule in ns/nspr20/config/rules.mk to generate
# the .$(OBJ_SUFFIX) file from the .c source file, then do the
# two-step linking hack below.

$(OBJDIR)/%: $(OBJDIR)/%.$(OBJ_SUFFIX)
	@$(MAKE_OBJDIR)
	rm -f $@ $(AIX_TMP)
	$(CC) $(AIX_LINK_OPTS) -o $(AIX_TMP) $< $(DIST)/lib/libnspr$(MOD_VERSION).a
	$(CC) -o $@ $(AIX_TMP) $(AIX_WRAP)
	rm -f $(AIX_TMP)

else

# All platforms that are not AIX pre-4.2.


ifeq ($(USE_PTHREADS), 1)
$(OBJDIR)/attach: $(OBJDIR)/attach.$(OBJ_SUFFIX)
	@$(MAKE_OBJDIR)
ifeq ($(OS_ARCH), AIX)
	$(CC) $< $(LDOPTS) $(LIBPLC) $(LIBPR) -lpthreads -o $@
else
ifeq ($(OS_ARCH),FreeBSD)
	$(CC) $< $(LDOPTS) $(LIBPLC) $(LIBPR) -lc_r -o $@
else
	$(CC) $< $(LDOPTS) $(LIBPLC) $(LIBPR) -lpthread -o $@
endif
endif
endif


$(OBJDIR)/%$(PROG_SUFFIX): $(OBJDIR)/%.$(OBJ_SUFFIX)
	@$(MAKE_OBJDIR)
ifeq ($(OS_ARCH), WINNT)
ifeq ($(OS_TARGET),WIN16)
	echo system windows >w16link
	echo name $@  >>w16link
	echo option map >>w16link
#	echo option CASEEXACT >>w16link
	echo option stack=16K >>w16link
	echo debug $(DEBUGTYPE) all >>w16link
	echo file >>w16link
	echo $< , >>w16link
	echo $(W16STDIO) >>w16link
	echo library  >>w16link
	echo $(LIBPR),	     >>w16link
	echo $(LIBPLC),		 >>w16link
	echo winsock.lib     >>w16link
	wlink @w16link.
else
ifeq ($(OS_TARGET),OS2)
	$(LINK) $(LDOPTS) $< $(LIBPLC) $(LIBPR) so32dll.lib tcp32dll.lib -MAP:$(@:.exe=.map) -out:$@
else
	link $(LDOPTS) $< $(LIBPLC) $(LIBPR) wsock32.lib -out:$@
endif
endif
else
	$(CC) $(XCFLAGS) $< $(LDOPTS) $(LIBPLC) $(LIBPR) $(EXTRA_LIBS) -o $@
endif

endif

export:: $(TARGETS)
install:: export
clean::
	rm -f $(TARGETS)

#
# Run the test programs with no arguments
#
# Test output goes to the file pointed to by the environment variable
# NSPR_TEST_LOGFILE, if set, else to /dev/null
#
ECHO = echo
PROGRAMS = $(notdir $(PROGS))
ifdef NSPR_TEST_LOGFILE
LOGFILE = $(NSPR_TEST_LOGFILE)
else
ifeq ($(OS_ARCH), WINNT)
LOGFILE = nul
else
LOGFILE = /dev/null
endif
endif

ifeq ($(OS_TARGET),Linux)
ECHO = /bin/echo
endif

ALWAYS:

runtests:: $(PROGS) ALWAYS
	@$(ECHO) "\nNSPR Test Results - $(OBJDIR)\n"
	@$(ECHO) "BEGIN\t\t\t`date`"
	@$(ECHO) "NSPR_TEST_LOGFILE\t$(LOGFILE)\n"
	@$(ECHO) "Test\t\t\tResult\n"
	@cd $(OBJDIR); for i in $(PROGRAMS); do					\
	$(ECHO) "$$i\c";										\
	./$$i >> $(LOGFILE) 2>&1 ;								\
	if  [ 0 = $$? ] ; then									\
		$(ECHO) "\t\t\tPassed";								\
	else													\
		$(ECHO) "\t\t\tFAILED";								\
	fi;														\
	done
	@$(ECHO) "\nEND\t\t`date`\n"
