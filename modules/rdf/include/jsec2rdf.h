/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
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

#ifndef _JSEC_2_RDF_H_
#define _JSEC_2_RDF_H_

#include "rdf.h"

typedef int16 JSec_Error;

#define JSec_OK ((JSec_Error)0x0000)
#define JSec_NullObject ((JSec_Error)0x0001)

typedef RDF_Resource JSec_Principal;
typedef RDF_Resource JSec_PrincipalUse;
typedef RDF_Resource JSec_Target;

NSPR_BEGIN_EXTERN_C

char *             RDFJSec_GetPrincipalURLString(char *principalID);
const char *       RDFJSec_PrincipalUseID(JSec_PrincipalUse prUse);

JSec_Error         RDFJSec_InitPrivilegeDB(); /* just use gNCDB */
JSec_Error         RDFJSec_SavePrivilegeDB(); 
JSec_Error         RDFJSec_ClosePrivilegeDB();

RDF_Cursor         RDFJSec_ListAllPrincipals();
JSec_Principal     RDFJSec_NextPrincipal(RDF_Cursor c);
JSec_Error         RDFJSec_ReleaseCursor(RDF_Cursor c);

JSec_Principal     RDFJSec_NewPrincipal(char* principalID);
JSec_Error         RDFJSec_AddPrincipal(JSec_Principal pr);
JSec_Error         RDFJSec_DeletePrincipal(JSec_Principal pr);
char*              RDFJSec_PrincipalID(JSec_Principal pr);
void *             RDFJSec_AttributeOfPrincipal(JSec_Principal pr, char* attributeType);
JSec_Error         RDFJSec_SetPrincipalAttribute(JSec_Principal pr, char* attributeType, void* attValue);

RDF_Cursor         RDFJSec_ListAllPrincipalUses(JSec_Principal pr);
JSec_PrincipalUse  RDFJSec_NextPrincipalUse(RDF_Cursor c);

JSec_PrincipalUse  RDFJSec_NewPrincipalUse(JSec_Principal pr, JSec_Target tr, char* priv);
JSec_Error         RDFJSec_AddPrincipalUse(JSec_Principal pr, JSec_PrincipalUse prUse);
JSec_Error         RDFJSec_DeletePrincipalUse (JSec_Principal pr, JSec_PrincipalUse prUse);

JSec_Error         RDFJSec_AddPrincipalUsePrivilege (JSec_PrincipalUse prUse, char* priv);
JSec_Error         RDFJSec_DeletePrincipalUsePrivilege (JSec_PrincipalUse prUse, char* priv);
char*              RDFJSec_PrivilegeOfPrincipalUse (JSec_PrincipalUse p);

JSec_Error         RDFJSec_AddTargetToPrincipalUse(JSec_PrincipalUse prUse, JSec_Target tr);
JSec_Error         RDFJSec_DeleteTargetToPrincipalUse(JSec_PrincipalUse prUse, JSec_Target tr);
JSec_Target        RDFJSec_TargetOfPrincipalUse (JSec_PrincipalUse p);

JSec_Target        RDFJSec_NewTarget(char* targetName, JSec_Principal pr);
char*              RDFJSec_GetTargetName(JSec_Target tr);
char*              RDFJSec_AttributeOfTarget(JSec_Target tr, char* attributeType);
JSec_Error         RDFJSec_SetTargetAttribute(JSec_Target tr, char* attributeType, char* attValue);

NSPR_END_EXTERN_C

#endif /* _JSEC_2_RDF_H_ */
