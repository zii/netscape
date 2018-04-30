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

/*
 * xp_md5.h: RSA MD5 algorithm
 *
 * For the most part this is RSA's public domain md5.h,
 * with a couple of new utility functions for us.
 *
 * Ari Luotonen
 */

#ifndef XP_MD5_H
#define XP_MD5_H

#include "xp_core.h"

XP_BEGIN_PROTOS
/*
 * XP_Md5Binary(data, digest)
 *	calculates the MD5 signature for 'data' of length 'len',
 *	and places the 16-byte binary signature into 'digest' which must
 *	be allocated by the caller.
 *
 */
void XP_Md5Binary(char *data, int len, unsigned char digest[16]);


/*
 * XP_Md5PCPrintable(data, len)
 *	returns a newly allocated string of given length, filled with
 *	a printable version of the MD5 signature for 'data' that is
 *	also a valid filename also on PC.
 *
 *	This maps only five bits to each char to make it work on the
 *	braindead, case-insensitive-filesystem PC, aaaarrgh.
 *
 *	So for each 5 bytes it takes, it gives 8 printable bytes,
 *	with bits taken from original data as follows:
 *
 *	[byte][bit]..[byte][bit]	byte=0..4, bit=1..8
 *
 *	[0][1]..[0][5]
 *	[0][6]..[1][2]
 *	[1][3]..[1][7]
 *	[1][8]..[2][4]
 *	[2][5]..[3][1]
 *	[3][2]..[3][6]
 *	[3][7]..[4][3]
 *	[4][4]..[4][8]
 *
 */
char *XP_Md5PCPrintable(char *data, int len);

XP_END_PROTOS

#endif /* ! XP_MD5_H */

