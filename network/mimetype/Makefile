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

DEPTH		= ../..

MODULE		= mimetype
LIBRARY_NAME	= mimetype

CSRCS		= \
	mkformat.c	\
	$(NULL)

EXPORTS=mkformat.h

include $(DEPTH)/config/config.mk

REQUIRES	= nspr2 network img layer util

include $(DEPTH)/config/rules.mk

#
# This converts mime.types to C source code,
#  and also to an HTML table that shows what's in it.
#
MIME_TYPES		= ./mime.types
MIME_TYPES_UNIX		= ./mime.types-unix
MIME_TYPES_NONUNIX	= ./mime.types-nonunix
AD2C			= sh $(DEPTH)/cmd/xfe/ad2c

mktypes.h: $(MIME_TYPES) $(MIME_TYPES_UNIX) $(MIME_TYPES_NONUNIX)
	rm -f $@
	@echo "generating $@ from $<..."			; \
	 (echo '/* Generated file - do not edit! */'		; \
	  echo ''						; \
	  cat $(MIME_TYPES) | grep -v '^#' | $(AD2C)		; \
	  echo ''						; \
	  echo '#ifdef XP_UNIX'					; \
	  cat $(MIME_TYPES_UNIX) | grep -v '^#' | $(AD2C)	; \
	  echo '#else  /* !XP_UNIX */'				; \
	  cat $(MIME_TYPES_NONUNIX) | grep -v '^#' | $(AD2C)	; \
	  echo '#endif /* !XP_UNIX */'				; \
	 ) > $@

mime-types.html: $(MIME_TYPES) $(MIME_TYPES_UNIX)
	rm -f $@
	@echo "generating $@ from $<..."				; \
	 (echo '<TITLE>Netscape MIME Types</TITLE>'			; \
	  echo '<H1 ALIGN=CENTER>Netscape MIME Types</H1>'		; \
	  echo '<CENTER>'						; \
	  echo '<TABLE BORDER CELLSPACING=0 CELLPADDING=5>'		; \
	  echo '<TR><TH></TH><TH>Content Type:</TH>'			; \
	  echo '<TH>Extensions:</TH><TH>Description:</TH></TR>'		; \
	  echo '<TR></TR><TR></TR><TR></TR>'	; \
	  cat $(MIME_TYPES) $(MIME_TYPES_UNIX) | grep -v '^#' |		   \
	  sed  's@exts="\([^"]*\)"[ 	]*[\]*@<TR><TD><TT>\1</TT></TD>@;  \
		s@desc="\([^"]*\)"[ 	]*[\]*@<TD>\1</TD>@;		   \
		s@enc=\([^ 	]*\)[ 	]*[\]*$$@<TD>encoding/\1</TD>@;	   \
		s@type=\([^ 	]*\)[ 	]*[\]*$$@<TD>\1</TD>@;		   \
		s@icon=\([^ 	]*\)[ 	]*[\]*$$@<TD><IMG SRC=\1></TD></TR>@'\
	  | sed 's/,/ /g'						  \
	  | awk '{if ( $$0 ~ /^<TR/ ) {printf "%s" , $$0}		  \
		  else {printf "%s\n" , $$0} }'				  \
	  | sed 's@\(<TR>\)\(<TD>.*</TD>\)\(<TD>.*</TD>\)\(<TD>.*</TD>\)\(<TD>.*</TD>\)\(</TR>\)$$@\1\5!\3!\2!\4\6@' \
	  | tr '!' '\012'						  \
	  | sed 's@<TD></TD>@<TD>\&nbsp;</TD>@'				; \
	  echo '</TABLE>'						; \
	  echo '</CENTER>'						; \
	 ) > $@

