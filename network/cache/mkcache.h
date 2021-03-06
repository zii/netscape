/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*-
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

#ifndef MKCACHE_H
#define MKCACHE_H

#include "xp.h"

#ifndef EXT_CACHE_H
#include "extcache.h"
#endif

/* trace variable for cache testing */
extern PRBool NET_CacheTraceOn;

PR_BEGIN_EXTERN_C

/* public accessor function for netcaster */
extern PRBool NET_CacheStore(net_CacheObject *cacheObject, URL_Struct *url_s, PRBool accept_partial_files);

PR_END_EXTERN_C

#endif /* MKCACHE_H */
