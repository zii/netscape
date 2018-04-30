/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * The contents of this file are subject to the Netscape Public License
 * Version 1.0 (the "NPL"); you may not use this file except in
 * compliance with the NPL.  You may obtain a copy of the NPL at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the NPL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
 * for the specific language governing rights and limitations under the
 * NPL.
 *
 * The Initial Developer of this code under the NPL is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1998 Netscape Communications Corporation.  All Rights
 * Reserved.
 */
/* 
   passwd.c --- reading passwords with Motif text fields.
   Created: Jamie Zawinski <jwz@netscape.com>, 21-Jul-94.
 */


#include "mozilla.h"
#include "xfe.h"

typedef struct {
  Boolean isTextField;
  char plaintext[1]; /* Actually allocated with variable length; conceptually,
		      *  it's as if it were "char plaintext[maxLength*2]".
		      *  See the malloc() in newPasswdUserData() below.
		      */
} PasswdUserData;

PasswdUserData* newPasswdUserData(int maxLength)
{
  PasswdUserData* res=(PasswdUserData*)malloc( sizeof(PasswdUserData)
					      +(maxLength*2)
					      );
  if (res)
    {
      res->isTextField=0;
      memset(res->plaintext,0,maxLength*2);
    }

  return res;
}

static void 
passwd_modify_cb (Widget text, XtPointer client_data, XtPointer call_data)
{

  if (   fe_isTextModifyVerifyCallbackInhibited()
      || (!fe_IsPasswdTextFormElement(text))
      )
    {
      XmTextVerifyCallbackStruct *vcb = (XmTextVerifyCallbackStruct *) call_data;
      PasswdUserData* passwdUserData=(PasswdUserData*)client_data;
      char *plaintext = passwdUserData->plaintext;
      int deletion_length = vcb->endPos - vcb->startPos;
      int insertion_length = vcb->text->length;
      int L = strlen (plaintext);
      int i;
      
      if (vcb->reason != XmCR_MODIFYING_TEXT_VALUE)
	return;
      
      /* If a deletion occurred, clone it. */
      if (deletion_length > 0)
	{
	  for (i = 0; i < (L + 1 - deletion_length); i++)
	    {
	      plaintext [vcb->startPos+i] = plaintext[vcb->endPos+i];
	      if (! plaintext [vcb->startPos+i])
		/* If we copied a null, we're done. */
		break;
	    }
	  L -= deletion_length;
	}
      
      /* If an insertion occurred, open up space for it. */
      if (insertion_length > 0)
	{
	  for (i = 0; i <= (L - vcb->startPos); i++)
	    plaintext [L + insertion_length - i] = plaintext [L - i];
	  L += insertion_length;

	  /* Now fill in the opened gap. */
	  for (i = 0; i < insertion_length; i++)
	    plaintext [vcb->startPos + i] = vcb->text->ptr [i];
	}
      
      /* Now modify the text to insert stars. */
      for (i = 0; i < insertion_length; i++)
	vcb->text->ptr [i] = '*';
    }
  
}

static void
passwd_destroy_cb (Widget text_field, XtPointer closure, XtPointer call_data)
{
  PasswdUserData* passwdUserData=0;
  char *plaintext = 0;
  int i;
  XtVaGetValues (text_field, XmNuserData, &passwdUserData, 0);
  if (!passwdUserData) return;
  XtVaSetValues (text_field, XmNuserData, 0, 0);
  plaintext = passwdUserData->plaintext;
  i = strlen (plaintext);
  while (i--) plaintext [i] = 0; /* paranoia about core files */
  free (passwdUserData);
}

void
fe_MarkPasswdTextAsFormElement(Widget text_field)
{
  PasswdUserData* passwdUserData=0;
  XtVaGetValues (text_field,
		 XmNuserData, &passwdUserData,
		 0);
  if (passwdUserData)
    passwdUserData->isTextField=1;
}

Boolean
fe_IsPasswdTextFormElement(Widget text_field)
{
  PasswdUserData* passwdUserData=0;

  XtVaGetValues (text_field,
		 XmNuserData, &passwdUserData,
		 0);
  return (  passwdUserData
	  ? ((passwdUserData->isTextField)!=0)
	  : 0
	  );
}

void
fe_SetupPasswdText (Widget text_field, int max_length)
{
  PasswdUserData* passwdUserData=0;
  if (max_length <= 0) abort ();
  XtVaGetValues (text_field, XmNuserData, &passwdUserData, 0);
  if (passwdUserData) return;    /* already initialized? */
  passwdUserData=newPasswdUserData(max_length);
  XtAddCallback (text_field, XmNmodifyVerifyCallback, passwd_modify_cb,
		 passwdUserData);
  XtAddCallback (text_field, XtNdestroyCallback, passwd_destroy_cb, 0);
  XtVaSetValues (text_field,
		 XmNuserData, passwdUserData,
		 XmNmaxLength, max_length,
		 0);

  /*
   * make sure the international input method does not come up for this
   * widget, since we want to hide the password
   */
  XmImUnregister (text_field);
}

char *
fe_GetPasswdText (Widget text_field)
{
  PasswdUserData* passwdUserData=0;
  XtVaGetValues (text_field, XmNuserData, &passwdUserData, 0);
  /* Return a copy to be analagous with GetValues of XmNvalue.
     The internal copy will be freed when the widget is destroyed. */

  /* passwdUserData->plaintext can't be null in the current declaration
   *  of the struct, 'cause it's declared as an array, but let's
   *  be careful.
   */
  return XP_STRDUP (  (passwdUserData && passwdUserData->plaintext)
		    ? passwdUserData->plaintext
		    : ""
		    );
}
