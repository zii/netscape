/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*-
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
/*******************************************************************************
 * Source date: 29 Jan 1997 02:28:10 GMT
 * netscape/fonts/nffbcpp public interface
 * Generated by jmc version 1.8 -- DO NOT EDIT
 ******************************************************************************/

#ifndef _Mnffbcpp_H_
#define _Mnffbcpp_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "jmc.h"

/*******************************************************************************
 * nffbcpp
 ******************************************************************************/

/* The type of the nffbcpp interface. */
struct nffbcppInterface;

/* The public type of a nffbcpp instance. */
typedef struct nffbcpp {
	const struct nffbcppInterface*	vtable;
} nffbcpp;

/* The inteface ID of the nffbcpp interface. */
#ifndef JMC_INIT_nffbcpp_ID
extern EXTERN_C_WITHOUT_EXTERN const JMCInterfaceID nffbcpp_ID;
#else
EXTERN_C const JMCInterfaceID nffbcpp_ID = { 0x076d7270, 0x687b1c3f, 0x3c252054, 0x75133743 };
#endif /* JMC_INIT_nffbcpp_ID */
/*******************************************************************************
 * nffbcpp Operations
 ******************************************************************************/

#define nffbcpp_getInterface(self, a, exception)	\
	(((self)->vtable->getInterface)(self, nffbcpp_getInterface_op, a, exception))

#define nffbcpp_addRef(self, exception)	\
	(((self)->vtable->addRef)(self, nffbcpp_addRef_op, exception))

#define nffbcpp_release(self, exception)	\
	(((self)->vtable->release)(self, nffbcpp_release_op, exception))

#define nffbcpp_hashCode(self, exception)	\
	(((self)->vtable->hashCode)(self, nffbcpp_hashCode_op, exception))

#define nffbcpp_equals(self, obj, exception)	\
	(((self)->vtable->equals)(self, nffbcpp_equals_op, obj, exception))

#define nffbcpp_clone(self, exception)	\
	(((self)->vtable->clone)(self, nffbcpp_clone_op, exception))

#define nffbcpp_toString(self, exception)	\
	(((self)->vtable->toString)(self, nffbcpp_toString_op, exception))

#define nffbcpp_finalize(self, exception)	\
	(((self)->vtable->finalize)(self, nffbcpp_finalize_op, exception))

#define nffbcpp_nfdoerID(self, exception)	\
	(((self)->vtable->nfdoerID)(self, nffbcpp_nfdoerID_op, exception))

#define nffbcpp_nffID(self, exception)	\
	(((self)->vtable->nffID)(self, nffbcpp_nffID_op, exception))

#define nffbcpp_nffbcID(self, exception)	\
	(((self)->vtable->nffbcID)(self, nffbcpp_nffbcID_op, exception))

#define nffbcpp_nffbpID(self, exception)	\
	(((self)->vtable->nffbpID)(self, nffbcpp_nffbpID_op, exception))

#define nffbcpp_nffbuID(self, exception)	\
	(((self)->vtable->nffbuID)(self, nffbcpp_nffbuID_op, exception))

#define nffbcpp_nffbcppID(self, exception)	\
	(((self)->vtable->nffbcppID)(self, nffbcpp_nffbcppID_op, exception))

#define nffbcpp_nffmiID(self, exception)	\
	(((self)->vtable->nffmiID)(self, nffbcpp_nffmiID_op, exception))

#define nffbcpp_nffpID(self, exception)	\
	(((self)->vtable->nffpID)(self, nffbcpp_nffpID_op, exception))

#define nffbcpp_nfrcID(self, exception)	\
	(((self)->vtable->nfrcID)(self, nffbcpp_nfrcID_op, exception))

#define nffbcpp_nfrfID(self, exception)	\
	(((self)->vtable->nfrfID)(self, nffbcpp_nfrfID_op, exception))

#define nffbcpp_nfstrmID(self, exception)	\
	(((self)->vtable->nfstrmID)(self, nffbcpp_nfstrmID_op, exception))

#define nffbcpp_nfdlmID(self, exception)	\
	(((self)->vtable->nfdlmID)(self, nffbcpp_nfdlmID_op, exception))

/*******************************************************************************
 * nffbcpp Interface
 ******************************************************************************/

struct netscape_jmc_JMCInterfaceID;
struct java_lang_Object;
struct java_lang_String;

struct nffbcppInterface {
	void*	(*getInterface)(struct nffbcpp* self, jint op, const JMCInterfaceID* a, JMCException* *exception);
	void	(*addRef)(struct nffbcpp* self, jint op, JMCException* *exception);
	void	(*release)(struct nffbcpp* self, jint op, JMCException* *exception);
	jint	(*hashCode)(struct nffbcpp* self, jint op, JMCException* *exception);
	jbool	(*equals)(struct nffbcpp* self, jint op, void* obj, JMCException* *exception);
	void*	(*clone)(struct nffbcpp* self, jint op, JMCException* *exception);
	const char*	(*toString)(struct nffbcpp* self, jint op, JMCException* *exception);
	void	(*finalize)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nfdoerID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nffID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nffbcID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nffbpID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nffbuID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nffbcppID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nffmiID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nffpID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nfrcID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nfrfID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nfstrmID)(struct nffbcpp* self, jint op, JMCException* *exception);
	const JMCInterfaceID*	(*nfdlmID)(struct nffbcpp* self, jint op, JMCException* *exception);
};

/*******************************************************************************
 * nffbcpp Operation IDs
 ******************************************************************************/

typedef enum nffbcppOperations {
	nffbcpp_getInterface_op,
	nffbcpp_addRef_op,
	nffbcpp_release_op,
	nffbcpp_hashCode_op,
	nffbcpp_equals_op,
	nffbcpp_clone_op,
	nffbcpp_toString_op,
	nffbcpp_finalize_op,
	nffbcpp_nfdoerID_op,
	nffbcpp_nffID_op,
	nffbcpp_nffbcID_op,
	nffbcpp_nffbpID_op,
	nffbcpp_nffbuID_op,
	nffbcpp_nffbcppID_op,
	nffbcpp_nffmiID_op,
	nffbcpp_nffpID_op,
	nffbcpp_nfrcID_op,
	nffbcpp_nfrfID_op,
	nffbcpp_nfstrmID_op,
	nffbcpp_nfdlmID_op
} nffbcppOperations;

/******************************************************************************/

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* _Mnffbcpp_H_ */
