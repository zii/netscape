#!gmake
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



DEPTH		= ../../..

include $(DEPTH)/config/config.mk

ifdef JAVA_OR_OJI
ifdef REGENERATE
DIRS		= classes
endif
endif

MODULE		= java
LIBRARY_NAME	= jsj

REQUIRES	= java js applet nspr img util layer

ifdef MOZ_OJI
CSRCS = jsj.c		  \
	jsj_JSObject.c	  \
	jsj_JavaArray.c	  \
	jsj_JavaClass.c	  \
	jsj_JavaObject.c  \
	jsj_JavaPackage.c \
	jsj_array.c	  \
	jsj_class.c	  \
	jsj_convert.c	  \
	jsj_field.c	  \
	jsj_hash.c	  \
	jsj_method.c	  \
	jsj_utils.c
else
CSRCS = \
	jsjava.c \
	jsStubs.c \
	$(NULL)
endif

ifdef MOZ_OJI
ifdef REGENERATE
JNI_GEN		= netscape.javascript.JSObject netscape.javascript.JSException
endif
else # MOZ_JAVA
JRI_GEN		= netscape.javascript.JSObject netscape.javascript.JSException
endif

ifdef JAVA_OR_OJI
EXPORTS		= jsjava.h \
		  $(JRI_GEN_DIR)/netscape_javascript_JSObject.h \
		  $(JRI_GEN_DIR)/netscape_javascript_JSException.h \
		  $(NULL)

else
EXPORTS = jsjava.h	 \
          $(NULL)
endif


include $(DEPTH)/config/rules.mk

######################################################################

# Generate jsj_nodl.c (so that you can check it in)
# These make rules only works on IRIX...sigh

ifeq ($(OS_ARCH),IRIX)
jsj_nodl.c: $(OBJDIR)/stubs.o Makefile $(DEPTH)/config/nodl.pl
	rm -f $@
	$(PERL) $(DEPTH)/config/nodl.pl "jsj_nodl_tab" \
	    `nm -Bn $(OBJDIR)/stubs.o | egrep Java_.*_stub | awk '{print $$3;}'` > $@
endif

ifdef JAVA_OR_OJI
$(OBJDIR)/stubs.o:					 \
	$(JRI_GEN_DIR)/netscape_javascript_JSObject.c	 \
	$(JRI_GEN_DIR)/netscape_javascript_JSException.c \
	$(NULL)
else
$(OBJDIR)/stubs.o:
endif

export:: install

ifndef REGENERATE

export:: jsj10.jar
	$(INSTALL) -m 444 jsj10.jar $(JAVA_DESTPATH)
	set tmpwd=`pwd`; cd $(JAVA_DESTPATH) ; unzip -o jsj10.jar ; cd $$tempwd 

endif
