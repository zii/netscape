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

#ifndef _NS_PRIVILEGE_TABLE_H_
#define _NS_PRIVILEGE_TABLE_H_

#include "prtypes.h"
#include "nsHashtable.h"
#include "nsTarget.h"
#include "nsPrivilege.h"
#include "nsCom.h"


class nsPrivilegeTable {

public:

	/* Public Methods */
	nsPrivilegeTable(void);
	virtual ~nsPrivilegeTable(void);

	PRInt32 size(void);

	PRBool isEmpty(void);

	virtual nsPrivilege * get(nsTarget *t);

	nsPrivilege * put(nsTarget *a, nsPrivilege *priv);

	nsPrivilege * remove(nsTarget *key);

	nsPrivilegeTable * clone(void);

	void clear(void);

	void Enumerate(nsHashtableEnumFunc aEnumFunc);

private:

	/* Private Field Accessors */
	nsHashtable * itsTable;
};

#endif /* _NS_PRIVILEGE_TABLE_H_ */
