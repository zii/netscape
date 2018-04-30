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


#include "sechash.h"
#include "xp_md5.h"
#include "xp_mem.h"
#include "xpassert.h"

/*
 * XP_Md5Binary(data, digest)
 *	calculates the MD5 signature for 'data' which is NULL-terminated,
 *	and places the 16-byte binary signature into 'digest' which must
 *	be allocated by the caller.
 *
 */
void XP_Md5Binary(char *data, int len, unsigned char digest[16])
{
    MD5_HashBuf(digest, (unsigned char *)data, len);
}


static char xp_pr[] = "0123456789abcdefghijklmnopqrstuv";

/*
 * XP_Md5PCPrintable(data, len)
 *      Makes a call to XP_Md5Binary, which turns a buffer of length 'len'
 *      into a 16 byte digest.  This routine then turns the 16 binary bytes
 *      into 24 readable bytes.  It is the responsibility of the caller
 *      to free this string.
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
PUBLIC char *XP_Md5PCPrintable(char *data, int len)
{
    unsigned char digest[16];
    char* buf = (char*) XP_ALLOC(25); /* 16 bytes -> 24 printable bytes */
    register int i, j;

    if ( buf == NULL ) return NULL;

    XP_Md5Binary(data, len, digest);

    /* Aaargh, somebody come up with a more mathematical formula to do this
       without hardcoded numbers.
     */
    for (i=j=0; i<15; i+=5, j+=8)
      {
	  buf[j  ] = xp_pr[                             (digest[i  ] >> 3)];
	  buf[j+1] = xp_pr[((digest[i  ] &   7) << 2) | (digest[i+1] >> 6)];
	  buf[j+2] = xp_pr[((digest[i+1] &  63) >> 1)                     ];
	  buf[j+3] = xp_pr[((digest[i+1] &   1) << 4) | (digest[i+2] >> 4)];
	  buf[j+4] = xp_pr[((digest[i+2] &  15) << 1) | (digest[i+3] >> 7)];
	  buf[j+5] = xp_pr[((digest[i+3] & 127) >> 2)                     ];
	  buf[j+6] = xp_pr[((digest[i+3] &   3) << 3) | (digest[i+4] >> 5)];
	  buf[j+7] = xp_pr[((digest[i+4] &  31)     )                     ];
      }

    buf[24] = '\0';

    return buf;
}
