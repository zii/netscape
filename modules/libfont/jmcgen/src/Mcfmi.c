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
 * Source date: 9 Apr 1997 21:45:13 GMT
 * netscape/fonts/cfmi module C stub file
 * Generated by jmc version 1.8 -- DO NOT EDIT
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "xp_mem.h"

/* Include the implementation-specific header: */
#include "Pcfmi.h"

/* Include other interface headers: */

/*******************************************************************************
 * cfmi Methods
 ******************************************************************************/

#ifndef OVERRIDE_cfmi_getInterface
JMC_PUBLIC_API(void*)
_cfmi_getInterface(struct cfmi* self, jint op, const JMCInterfaceID* iid, JMCException* *exc)
{
	if (memcmp(iid, &cfmi_ID, sizeof(JMCInterfaceID)) == 0)
		return cfmiImpl2cfmi(cfmi2cfmiImpl(self));
	return _cfmi_getBackwardCompatibleInterface(self, iid, exc);
}
#endif

#ifndef OVERRIDE_cfmi_addRef
JMC_PUBLIC_API(void)
_cfmi_addRef(struct cfmi* self, jint op, JMCException* *exc)
{
	cfmiImplHeader* impl = (cfmiImplHeader*)cfmi2cfmiImpl(self);
	impl->refcount++;
}
#endif

#ifndef OVERRIDE_cfmi_release
JMC_PUBLIC_API(void)
_cfmi_release(struct cfmi* self, jint op, JMCException* *exc)
{
	cfmiImplHeader* impl = (cfmiImplHeader*)cfmi2cfmiImpl(self);
	if (--impl->refcount == 0) {
		cfmi_finalize(self, exc);
	}
}
#endif

#ifndef OVERRIDE_cfmi_hashCode
JMC_PUBLIC_API(jint)
_cfmi_hashCode(struct cfmi* self, jint op, JMCException* *exc)
{
	return (jint)self;
}
#endif

#ifndef OVERRIDE_cfmi_equals
JMC_PUBLIC_API(jbool)
_cfmi_equals(struct cfmi* self, jint op, void* obj, JMCException* *exc)
{
	return self == obj;
}
#endif

#ifndef OVERRIDE_cfmi_clone
JMC_PUBLIC_API(void*)
_cfmi_clone(struct cfmi* self, jint op, JMCException* *exc)
{
	cfmiImpl* impl = cfmi2cfmiImpl(self);
	cfmiImpl* newImpl = (cfmiImpl*)malloc(sizeof(cfmiImpl));
	if (newImpl == NULL) return NULL;
	memcpy(newImpl, impl, sizeof(cfmiImpl));
	((cfmiImplHeader*)newImpl)->refcount = 1;
	return newImpl;
}
#endif

#ifndef OVERRIDE_cfmi_toString
JMC_PUBLIC_API(const char*)
_cfmi_toString(struct cfmi* self, jint op, JMCException* *exc)
{
	return NULL;
}
#endif

#ifndef OVERRIDE_cfmi_finalize
JMC_PUBLIC_API(void)
_cfmi_finalize(struct cfmi* self, jint op, JMCException* *exc)
{
	/* Override this method and add your own finalization here. */
	XP_FREEIF(self);
}
#endif

/*******************************************************************************
 * Jump Tables
 ******************************************************************************/

const struct cfmiInterface cfmiVtable = {
	_cfmi_getInterface,
	_cfmi_addRef,
	_cfmi_release,
	_cfmi_hashCode,
	_cfmi_equals,
	_cfmi_clone,
	_cfmi_toString,
	_cfmi_finalize,
	_cfmi_GetValue,
	_cfmi_ListAttributes
};

/*******************************************************************************
 * Factory Operations
 ******************************************************************************/

JMC_PUBLIC_API(cfmi*)
cfmiFactory_Create(JMCException* *exception, const char* a, const char* b, const char* c, jint d, jint e, jint f, jint g, jint h, jint i, jint j)
{
	cfmiImplHeader* impl = (cfmiImplHeader*)XP_NEW_ZAP(cfmiImpl);
	cfmi* self;
	if (impl == NULL) {
		JMC_EXCEPTION(exception, JMCEXCEPTION_OUT_OF_MEMORY);
		return NULL;
	}
	self = cfmiImpl2cfmi(impl);
	impl->vtablecfmi = &cfmiVtable;
	impl->refcount = 1;
	_cfmi_init(self, exception, a, b, c, d, e, f, g, h, i, j);
	if (JMC_EXCEPTION_RETURNED(exception)) {
		XP_FREE(impl);
		return NULL;
	}
	return self;
}

