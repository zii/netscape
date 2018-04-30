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
 * Source date: 9 Apr 1997 21:45:12 GMT
 * netscape/fonts/crc module C header file
 * Generated by jmc version 1.8 -- DO NOT EDIT
 ******************************************************************************/

#ifndef _Mcrc_H_
#define _Mcrc_H_

#include "jmc.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*******************************************************************************
 * crc
 ******************************************************************************/

/* The type of the crc interface. */
struct crcInterface;

/* The public type of a crc instance. */
typedef struct crc {
	const struct crcInterface*	vtable;
} crc;

/* The inteface ID of the crc interface. */
#ifndef JMC_INIT_crc_ID
extern EXTERN_C_WITHOUT_EXTERN const JMCInterfaceID crc_ID;
#else
EXTERN_C const JMCInterfaceID crc_ID = { 0x241a4e5e, 0x465b4148, 0x5d5a481e, 0x695e4c7f };
#endif /* JMC_INIT_crc_ID */
/*******************************************************************************
 * crc Operations
 ******************************************************************************/

#define crc_getInterface(self, a, exception)	\
	(((self)->vtable->getInterface)(self, crc_getInterface_op, a, exception))

#define crc_addRef(self, exception)	\
	(((self)->vtable->addRef)(self, crc_addRef_op, exception))

#define crc_release(self, exception)	\
	(((self)->vtable->release)(self, crc_release_op, exception))

#define crc_hashCode(self, exception)	\
	(((self)->vtable->hashCode)(self, crc_hashCode_op, exception))

#define crc_equals(self, a, exception)	\
	(((self)->vtable->equals)(self, crc_equals_op, a, exception))

#define crc_clone(self, exception)	\
	(((self)->vtable->clone)(self, crc_clone_op, exception))

#define crc_toString(self, exception)	\
	(((self)->vtable->toString)(self, crc_toString_op, exception))

#define crc_finalize(self, exception)	\
	(((self)->vtable->finalize)(self, crc_finalize_op, exception))

#define crc_GetMajorType(self, exception)	\
	(((self)->vtable->GetMajorType)(self, crc_GetMajorType_op, exception))

#define crc_GetMinorType(self, exception)	\
	(((self)->vtable->GetMinorType)(self, crc_GetMinorType_op, exception))

#define crc_IsEquivalent(self, a, b, exception)	\
	(((self)->vtable->IsEquivalent)(self, crc_IsEquivalent_op, a, b, exception))

#define crc_GetPlatformData(self, exception)	\
	(((self)->vtable->GetPlatformData)(self, crc_GetPlatformData_op, exception))

#define crc_SetPlatformData(self, a, exception)	\
	(((self)->vtable->SetPlatformData)(self, crc_SetPlatformData_op, a, exception))

/*******************************************************************************
 * crc Interface
 ******************************************************************************/

struct netscape_jmc_JMCInterfaceID;
struct java_lang_Object;
struct java_lang_String;
struct netscape_fonts_PlatformRCData;
struct netscape_fonts_PlatformRCDataStar;

struct crcInterface {
	void*	(*getInterface)(struct crc* self, jint op, const JMCInterfaceID* a, JMCException* *exception);
	void	(*addRef)(struct crc* self, jint op, JMCException* *exception);
	void	(*release)(struct crc* self, jint op, JMCException* *exception);
	jint	(*hashCode)(struct crc* self, jint op, JMCException* *exception);
	jbool	(*equals)(struct crc* self, jint op, void* a, JMCException* *exception);
	void*	(*clone)(struct crc* self, jint op, JMCException* *exception);
	const char*	(*toString)(struct crc* self, jint op, JMCException* *exception);
	void	(*finalize)(struct crc* self, jint op, JMCException* *exception);
	jint	(*GetMajorType)(struct crc* self, jint op, JMCException* *exception);
	jint	(*GetMinorType)(struct crc* self, jint op, JMCException* *exception);
	jint	(*IsEquivalent)(struct crc* self, jint op, jint a, jint b, JMCException* *exception);
	struct rc_data	(*GetPlatformData)(struct crc* self, jint op, JMCException* *exception);
	jint	(*SetPlatformData)(struct crc* self, jint op, struct rc_data * a, JMCException* *exception);
};

/*******************************************************************************
 * crc Operation IDs
 ******************************************************************************/

typedef enum crcOperations {
	crc_getInterface_op,
	crc_addRef_op,
	crc_release_op,
	crc_hashCode_op,
	crc_equals_op,
	crc_clone_op,
	crc_toString_op,
	crc_finalize_op,
	crc_GetMajorType_op,
	crc_GetMinorType_op,
	crc_IsEquivalent_op,
	crc_GetPlatformData_op,
	crc_SetPlatformData_op
} crcOperations;

/*******************************************************************************
 * Writing your C implementation: "crc.h"
 * *****************************************************************************
 * You must create a header file named "crc.h" that implements
 * the struct crcImpl, including the struct crcImplHeader
 * as it's first field:
 * 
 * 		#include "Mcrc.h" // generated header
 * 
 * 		struct crcImpl {
 * 			crcImplHeader	header;
 * 			<your instance data>
 * 		};
 * 
 * This header file will get included by the generated module implementation.
 ******************************************************************************/

/* Forward reference to the user-defined instance struct: */
typedef struct crcImpl	crcImpl;


/* This struct must be included as the first field of your instance struct: */
typedef struct crcImplHeader {
	const struct crcInterface*	vtablecrc;
	jint		refcount;
} crcImplHeader;

/*******************************************************************************
 * Instance Casting Macros
 * These macros get your back to the top of your instance, crc,
 * given a pointer to one of its interfaces.
 ******************************************************************************/

#undef  crcImpl2nfrc
#define crcImpl2nfrc(crcImplPtr) \
	((nfrc*)((char*)(crcImplPtr) + offsetof(crcImplHeader, vtablecrc)))

#undef  nfrc2crcImpl
#define nfrc2crcImpl(nfrcPtr) \
	((crcImpl*)((char*)(nfrcPtr) - offsetof(crcImplHeader, vtablecrc)))

#undef  crcImpl2crc
#define crcImpl2crc(crcImplPtr) \
	((crc*)((char*)(crcImplPtr) + offsetof(crcImplHeader, vtablecrc)))

#undef  crc2crcImpl
#define crc2crcImpl(crcPtr) \
	((crcImpl*)((char*)(crcPtr) - offsetof(crcImplHeader, vtablecrc)))

/*******************************************************************************
 * Operations you must implement
 ******************************************************************************/


extern JMC_PUBLIC_API(void*)
_crc_getBackwardCompatibleInterface(struct crc* self, const JMCInterfaceID* iid,
	JMCException* *exception);

extern JMC_PUBLIC_API(void)
_crc_init(struct crc* self, JMCException* *exception, jint a, jint b, void** c, jsize c_length);

extern JMC_PUBLIC_API(void*)
_crc_getInterface(struct crc* self, jint op, const JMCInterfaceID* a, JMCException* *exception);

extern JMC_PUBLIC_API(void)
_crc_addRef(struct crc* self, jint op, JMCException* *exception);

extern JMC_PUBLIC_API(void)
_crc_release(struct crc* self, jint op, JMCException* *exception);

extern JMC_PUBLIC_API(jint)
_crc_hashCode(struct crc* self, jint op, JMCException* *exception);

extern JMC_PUBLIC_API(jbool)
_crc_equals(struct crc* self, jint op, void* a, JMCException* *exception);

extern JMC_PUBLIC_API(void*)
_crc_clone(struct crc* self, jint op, JMCException* *exception);

extern JMC_PUBLIC_API(const char*)
_crc_toString(struct crc* self, jint op, JMCException* *exception);

extern JMC_PUBLIC_API(void)
_crc_finalize(struct crc* self, jint op, JMCException* *exception);

extern JMC_PUBLIC_API(jint)
_crc_GetMajorType(struct crc* self, jint op, JMCException* *exception);

extern JMC_PUBLIC_API(jint)
_crc_GetMinorType(struct crc* self, jint op, JMCException* *exception);

extern JMC_PUBLIC_API(jint)
_crc_IsEquivalent(struct crc* self, jint op, jint a, jint b, JMCException* *exception);

extern JMC_PUBLIC_API(struct rc_data)
_crc_GetPlatformData(struct crc* self, jint op, JMCException* *exception);

extern JMC_PUBLIC_API(jint)
_crc_SetPlatformData(struct crc* self, jint op, struct rc_data * a, JMCException* *exception);

/*******************************************************************************
 * Factory Operations
 ******************************************************************************/

JMC_PUBLIC_API(crc*)
crcFactory_Create(JMCException* *exception, jint a, jint b, void** c, jsize c_length);

/******************************************************************************/

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* _Mcrc_H_ */