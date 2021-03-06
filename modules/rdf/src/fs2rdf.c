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
   This file implements file system support for the rdf data model.
   For more information on this file, contact rjc or guha 
   For more information on RDF, look at the RDF section of www.mozilla.org
*/

#include "atalk.h"
#include "fs2rdf.h"
#include "glue.h"
#include "mcf.h"

	/* external string references in allxpstr */
extern	int	RDF_UNABLETODELETEFILE, RDF_UNABLETODELETEFOLDER;

#define IMPORT_LIST_SIZE 8

  	/* XXX localization */
char	*importList[IMPORT_LIST_SIZE] = {"Favorites", "NC:Bookmarks", "Recent", "NC:Bookmarks",
					"Start Menu", "NC:Bookmarks", "Desktop", "NC:LocalFiles"};



void
importForProfile (char *dir, const char *uname)
{
  int32 n = 0;
  char* pn = getMem(100 + strlen(dir));
  char* name = getMem(100 + strlen(uname));
  RDF_Resource item;
  RDF_Resource parent;
  while (n < IMPORT_LIST_SIZE) {
    sprintf(pn, "%s%s/", dir, importList[n++]);
    item = RDF_GetResource(NULL, pn, 1);
    parent = RDF_GetResource(NULL, importList[n++], 1);
    sprintf(name, "%s IE %s", uname,  importList[n-2]);
    remoteStoreAdd(gRemoteStore, item, gCoreVocab->RDF_name, copyString(name), 
                   RDF_STRING_TYPE, 1);
    remoteStoreAdd(gRemoteStore, item, gCoreVocab->RDF_parent, parent, RDF_RESOURCE_TYPE, 1);   
  }
  freeMem(pn);
  freeMem(name);
}



void
GuessIEBookmarks (void)
{
#ifdef XP_WIN
  RDF_Resource bmk = RDF_GetResource(NULL, "NC:Bookmarks", true);
  PRDir* ProfilesDir = OpenDir("file:///c|/winnt/profiles/");
  if (!ProfilesDir) {
  	/* XXX localization */
    importForProfile("file:///c|/windows/", "Your");
  } else {
    int32 n = PR_SKIP_BOTH;
    PRDirEntry	*de;
    while (de = PR_ReadDir(ProfilesDir, n++)) {
      if (strcmp(de->name, "Administrator") && strcmp(de->name, "Default User") && 
          strcmp(de->name, "All Users")) {
        char* dir = getMem(100 + strlen(de->name));
        sprintf(dir, "file:///c|/winnt/profiles/%s/", de->name);
        importForProfile(dir, de->name);
        freeMem(dir);
      }
    }
    PR_CloseDir(ProfilesDir);
  }
#endif
}



char *
getVolume(int16 volNum, PRBool afpVols)
{
	char			*url = NULL;

#ifdef	XP_MAC
	AFPXVolMountInfo	afpInfo;
	ParamBlockRec		pb;
	char			*encoded, str[64], *temp1, *temp2;
	PRBool			isAfpVol;

	XP_BZERO((void *)&pb, sizeof(pb));
	pb.volumeParam.ioCompletion = NULL;
	pb.volumeParam.ioVolIndex = volNum + 1;
	pb.volumeParam.ioNamePtr = (void *)str;
	if (!PBGetVInfo(&pb,FALSE))	{
		/* network volumes (via AFP) should be represented
		   by afp URLS instead of file URLs */
		
		isAfpVol = isAFPVolume(pb.volumeParam.ioVRefNum);
		if ((afpVols == PR_FALSE) && (isAfpVol == PR_FALSE))
		{
			str[1+(unsigned)str[0]] = '\0';
			if ((encoded = NET_Escape((char *)&str[1], URL_XALPHAS)) != NULL)
			{
				url = PR_smprintf("file:///%s/", encoded);
				XP_FREE(encoded);
			}
		}
		else if ((afpVols == PR_TRUE) && (isAfpVol == PR_TRUE))
		{
			XP_BZERO((void *)&afpInfo, sizeof(afpInfo));
			afpInfo.length = (short)sizeof(afpInfo);

			pb.ioParam.ioCompletion = NULL;
			/* use pb.ioParam.ioVRefNum */
			pb.ioParam.ioBuffer = (Ptr)&afpInfo;
			
			if (!PBGetVolMountInfo(&pb))
			{
				str[1+(unsigned)str[0]] = '\0';
				
				temp1 = getMem(1024);
				temp2 = getMem(1024);

				strcpy(temp1, "afp:/at/");
				/* server name */
				strncpy((void *)temp2, &afpInfo.AFPData[afpInfo.serverNameOffset-30+1],
					(unsigned int)afpInfo.AFPData[afpInfo.serverNameOffset-30]);
				temp2[(unsigned int)afpInfo.AFPData[afpInfo.serverNameOffset-30]] = '\0';
				strcat(temp1, (void *)NET_Escape((void *)temp2, URL_XALPHAS));
				strcat(temp1, ":");
				/* zone name */
				strncpy((void *)temp2, &afpInfo.AFPData[afpInfo.zoneNameOffset-30+1],
					(unsigned int)afpInfo.AFPData[afpInfo.zoneNameOffset-30]);
				temp2[(unsigned int)afpInfo.AFPData[afpInfo.zoneNameOffset-30]] = '\0';
				strcat(temp1, (void *)NET_Escape((void *)temp2, URL_XALPHAS));
				strcat(temp1, "/");
				/* volume name */
				strcat(temp1, NET_Escape((char *)&str[1], URL_XALPHAS));
				strcat(temp1,"/");
				url = copyString(temp1);
				
				freeMem(temp1);
				freeMem(temp2);
			}
		}
	}
#endif

#ifdef	XP_WIN
	UINT			driveType;
	char			str[32];

	/* Windows-specific method for getting drive info without touching the drives (Dave H.) */
	sprintf(str, "%c:\\", volNum + 'A');
	driveType = GetDriveType(str);
	if (driveType != DRIVE_UNKNOWN && driveType != DRIVE_NO_ROOT_DIR)
	{
		url = PR_smprintf("file:///%c|/", volNum + 'A');
	}
#endif

#ifdef  XP_UNIX
	if (volNum == 0)
	{
		url = PR_smprintf("file:///");
	}
#endif

	return(url);
}



PRDir *
OpenDir(char *name)
{
	PRDir		*d = NULL;

	if (startsWith("file:///", name))
	{
		d = CallPROpenDirUsingFileURL(name);
	}
	return(d);
}



RDFT
MakeLFSStore (char* url)
{
	RDFT		ntr;

	if ((ntr = (RDFT)getMem(sizeof(struct RDF_TranslatorStruct))) != NULL)
	{
		ntr->assert = fsAssert;
		ntr->unassert = fsUnassert;
		ntr->getSlotValue = fsGetSlotValue;
		ntr->getSlotValues = fsGetSlotValues;
		ntr->hasAssertion = fsHasAssertion;
		ntr->nextValue = fsNextValue;
		ntr->disposeCursor = fsDisposeCursor;
		ntr->url = copyString(url);
	}
	return(ntr);
}



PRBool
fsAssert (RDFT rdf, RDF_Resource u, RDF_Resource s, void* v, 
		   RDF_ValueType type, PRBool tv)
{
	PRBool			retVal = PR_FALSE;
#ifdef	XP_MAC
	AEAddressDesc		finderAddr = { typeNull, NULL };
	AEDescList		selection = { typeNull, NULL };
	AppleEvent		theEvent = { typeNull, NULL }, theReply = { typeNull, NULL };
	FSSpec			fss;
	OSErr			err;
	ProcessSerialNumber	finderPSN = { 0, kNoProcess };
	char			*errorMsg;
#endif

	if ((startsWith("file://", resourceID(u))) && (s == gNavCenter->RDF_Command))
	{
#ifdef	XP_MAC
		if (((RDF_Resource)v) == gNavCenter->RDF_Command_Reveal)
		{
			/* reveal item in Finder */
			retVal = PR_TRUE;
			if ((err = nativeMacPathname(resourceID(u), &fss)) != noErr)	{}
			else if ((err = getPSNbyTypeSig(&finderPSN, 'FNDR', 'MACS')) != noErr)	{}
			else if ((err = AECreateDesc(typeProcessSerialNumber, &finderPSN,
				sizeof(ProcessSerialNumber), &finderAddr)) != noErr)	{}
			else if ((err = AECreateAppleEvent(kAEFinderEvents /* kAEFinderSuite */,
				kAERevealSelection, &finderAddr, kAutoGenerateReturnID,
				kAnyTransactionID, &theEvent)) != noErr)	{}
			else if ((err = AECreateList (NULL, 0, false, &selection)) != noErr)	{}
			else if ((err = AEPutPtr (&selection, 0, typeFSS, &fss, sizeof(FSSpec))) != noErr)	{}
			else if ((err = AEPutParamDesc (&theEvent, keySelection, &selection)) != noErr)	{}
			else err = AESend (&theEvent, &theReply, kAENoReply, kAENormalPriority,
				kAEDefaultTimeout, NULL, NULL);

			if (err == noErr)
			{
				SetFrontProcess(&finderPSN);
			}
			else
			{
				if ((errorMsg = PR_smprintf("Error %d", (int)err)) != NULL)
				{
					FE_Alert(NULL, errorMsg);
					XP_FREE(errorMsg);
				}
			}

			if (finderAddr.dataHandle != NULL)	AEDisposeDesc(&finderAddr);
			if (selection.dataHandle != NULL)	AEDisposeDesc (&selection);
			if (theEvent.dataHandle != NULL)	AEDisposeDesc(&theEvent);
			if (theReply.dataHandle != NULL)	AEDisposeDesc(&theReply);
		}
#endif
	}
	return(retVal);
}



#ifdef	XP_MAC
OSErr
nativeMacPathname(char *fileURL, FSSpec *fss)
{
	OSErr		err = paramErr;
	char		*macURL = NULL, *token, *url, *escapedURL, *temp, *pascalStr;

	XP_ASSERT(fileURL != NULL);
	if (fileURL == NULL)	return(NULL);

	if (!startsWith("file:///", fileURL))	return(NULL);
	if (!(url = copyString(fileURL + strlen("file:///"))))	return(NULL);

	token = strtok(url, "/");
	while (token != NULL)
	{
		*token;
		if ((escapedURL = unescapeURL(token)) == NULL)
		{
			if (macURL != NULL)
			{
				freeMem(macURL);
				macURL = NULL;
			}
			break;			
		}
		if (macURL == NULL)
		{
			macURL = escapedURL;
		}
		else
		{
			temp = append2Strings(macURL, ":");
			freeMem(macURL);
			if (temp == NULL)
			{
				macURL = NULL;
				break;
			}
			macURL = append2Strings(temp, escapedURL);
			freeMem(temp);
			if (macURL == NULL)
			{
				break;
			}
			freeMem(escapedURL);
		}
		token = strtok(NULL, "/");
	}
	if (endsWith("/", fileURL))
	{
		temp = append2Strings(macURL, ":");
		freeMem(macURL);
		macURL = temp;
	}
	freeMem(url);
	if (macURL != NULL)
	{
		if ((pascalStr = getMem(strlen(macURL) + 3)) != NULL)
		{
			pascalStr[0] = strlen(macURL);
			strcpy(&pascalStr[1], macURL);
			err = FSMakeFSSpec(0, 0L, (void *)pascalStr, fss);
			freeMem(pascalStr);
		}
		freeMem(macURL);
	}
	return(err);
}



OSErr
getPSNbyTypeSig(ProcessSerialNumber *thePSN, OSType pType, OSType pSignature)
{
	OSErr			err;
	ProcessInfoRec		pInfo;

	thePSN->highLongOfPSN=0L;
	thePSN->lowLongOfPSN=kNoProcess;
	while (!(err=GetNextProcess(thePSN)))
	{
		if ((thePSN->highLongOfPSN==0L) && (thePSN->lowLongOfPSN==kNoProcess))
		{
			err=procNotFound;
			break;
		}
		pInfo.processInfoLength=sizeof(ProcessInfoRec);
		pInfo.processName=NULL;
		pInfo.processLocation=NULL;
		pInfo.processAppSpec=NULL;
		if ((err=GetProcessInformation(thePSN,&pInfo)) != noErr)	break;
		if ((pInfo.processType==pType) && (pInfo.processSignature==pSignature))	break;
	}
	return(err);
}
#endif



PRBool
fsRemoveFile(char *filePathname, PRBool justCheckWriteAccess)
{
	PRBool		errFlag = true;

	if (justCheckWriteAccess == true)
	{
		errFlag = ((!CallPRWriteAccessFileUsingFileURL(filePathname)) ? false:true);
	}
	else
	{
		if (!CallPRWriteAccessFileUsingFileURL(filePathname))
		{
			if (!CallPRDeleteFileUsingFileURL(filePathname))
			{
				errFlag = false;
			}
		}
		if (errFlag == true)
		{
			FE_Alert(((MWContext *)gRDFMWContext()),
				PR_smprintf(XP_GetString(RDF_UNABLETODELETEFILE),
				filePathname));
		}
	}
	return(errFlag);
}



PRBool
fsRemoveDir(char *filePathname, PRBool justCheckWriteAccess)
{
	PRBool		dirFlag, errFlag = false;
	PRDir		*d, *tempD;
	PRDirEntry	*de;
	char		*base, *dirStr, *fileStr;
	int		len, n = PR_SKIP_BOTH;

	if (filePathname == NULL)			return(true);
	if ((d = OpenDir(filePathname)) == NULL)	return(true);

	while ((de = PR_ReadDir(d, (PRDirFlags)(n++))) != NULL)
	{
		base = NET_Escape(de->name, URL_XALPHAS);
		if (base == NULL)	return(true);
		fileStr = append2Strings(filePathname, base);

		XP_FREE(base);
		if (fileStr == NULL)	return(true);
		dirFlag = (((tempD = OpenDir(fileStr)) != NULL)	? true:false);
		if (tempD != NULL)
		{

			PR_CloseDir(tempD);
		}

		if (dirFlag)
		{
			dirStr = append2Strings(fileStr, "/");
			errFlag = fsRemoveDir(dirStr, justCheckWriteAccess);
			if (dirStr != NULL)	freeMem(dirStr);
		}
		else
		{
			errFlag = fsRemoveFile(fileStr, justCheckWriteAccess);
		}

		freeMem(fileStr);
		if (errFlag == true)	break;
	}


	PR_CloseDir(d);

	if (errFlag == false)
	{
		if ((dirStr = copyString(filePathname)) != NULL)
		{
			len = strlen(dirStr)-1;
			if (dirStr[len] == '/')
			{
				dirStr[len] = '\0';
			}
			if (justCheckWriteAccess == true)
			{
				errFlag = fsRemoveFile(dirStr, justCheckWriteAccess);
			}
			else
			{
				errFlag = (CallPR_RmDirUsingFileURL(dirStr) != 0);

				if (errFlag == true)
				{
					FE_Alert(((MWContext *)gRDFMWContext()),
						PR_smprintf(XP_GetString(RDF_UNABLETODELETEFOLDER),
						filePathname));
				}
			}
			freeMem(dirStr);
		}
	}

	return(errFlag);
}



PRBool
fsUnassert (RDFT mcf, RDF_Resource u, RDF_Resource s, void* v, RDF_ValueType type)
{
	char		*filePathname;
	PRBool		retVal = false;

	if ((s == gCoreVocab->RDF_parent) && (type == RDF_RESOURCE_TYPE) &&
		(resourceType(u) == LFS_RT) && (containerp(v)) && 
		(resourceType((RDF_Resource)v) == LFS_RT) &&
		(startsWith(resourceID((RDF_Resource)v),  resourceID(u))))
	{
		filePathname =  resourceID((RDF_Resource)u);
		if (filePathname[strlen(filePathname)-1] == '/')
		{
			if (!fsRemoveDir(filePathname, true))
			{
				if (!fsRemoveDir(filePathname, false))
				{
					retVal = true;
				}
			}
		}
		else
		{
			if (!fsRemoveFile(filePathname, true))
			{
				if (!fsRemoveFile(filePathname, false))
				{
					retVal = true;
				}
			}
		}

		if (retVal == true)
		{
			sendNotifications2(mcf, RDF_DELETE_NOTIFY,
				u, s, v, type, true);
		}
		
	/* XXX hack: always return true (even if file/dir deletion fails)
		     to prevent an assertion going into the localstore,
		     which would hide a file/dir that still exists */

		retVal = true;
	}

	return(retVal);
}



PRBool
fsHasAssertion (RDFT rdf, RDF_Resource u, RDF_Resource s, void* v, 
		       RDF_ValueType type, PRBool tv)
{
	PRBool		ans = 0;
	PRDir		*d;
	PRDirEntry	*de;
	char		*filePathname, *name;
	int		len, n=0;

	if ((s == gCoreVocab->RDF_parent) && (type == RDF_RESOURCE_TYPE) &&
		(resourceType(u) == LFS_RT) && (containerp(v)) && 
		(resourceType((RDF_Resource)v) == LFS_RT) &&
		(startsWith(resourceID((RDF_Resource)v),  resourceID(u))))
	{
		d = OpenDir(resourceID((RDF_Resource)v));
		if ((filePathname = copyString(resourceID(u))) == NULL)
		{
			return(0);
		}

		len = strlen(filePathname)-1;
		if (filePathname[len] == '/')
		{
			filePathname[len] = '\0';
		}
		name = unescapeURL(&filePathname[ 1 + revCharSearch(XP_DIRECTORY_SEPARATOR,
				filePathname)]);
		if (name == NULL)
		{
			freeMem(filePathname);
			return(0);
		}

		while ((de = PR_ReadDir(d, (PRDirFlags)(n++))) != NULL)
		{
			if (strcmp(name, de->name) == 0)
			{
				ans = 1;
				break;
			}
		}

		PR_CloseDir(d);
		XP_FREE(name);
		freeMem(filePathname);
		return ans;
	}
	else
	{
		return(0);
	}
}



void *
fsGetSlotValue (RDFT rdf, RDF_Resource u, RDF_Resource s, RDF_ValueType type, PRBool inversep,  PRBool tv)
{
	PRBool			ans = PR_FALSE;
	PRFileInfo		fn;
	PRStatus		err;
	PRTime			oneMillion, dateVal;
	char			buffer[128], *pathname, *url;
	void			*retVal = NULL;
	int			len, n;
	int32			creationTime, modifyTime;
	struct tm		*time;

#ifdef	XP_MAC
	FInfo			fndrInfo;
	FSSpec			fss;
#endif

	if (!startsWith("file://", resourceID(u)))	return(NULL);

	if ((s == gCoreVocab->RDF_name) && (type == RDF_STRING_TYPE) && (tv))
	{
		if ((pathname = copyString(resourceID(u))) != NULL)
		{
			if ((len = strlen(pathname)) > 0)
			{
				if (pathname[len-1] == '/')  pathname[--len] = '\0';
				n = revCharSearch('/', pathname);
				retVal = (void *)unescapeURL(&pathname[n+1]);
				freeMem(pathname);
			}
		}
	}
	else if ((s == gWebData->RDF_size) && (type == RDF_INT_TYPE) && (tv))
	{
		if ((pathname = resourceID(u)) != NULL)
		{
			if ((url = unescapeURL(&pathname[FS_URL_OFFSET])) != NULL)
			{
				err=PR_GetFileInfo(url, &fn);
				if (!err)	retVal = (void *)fn.size;
				XP_FREE(url);
			}
		}
	}
	else if ((s == gWebData->RDF_description) && (type == RDF_STRING_TYPE) && (tv))
	{
		if ((pathname = resourceID(u)) != NULL)
		{
			if ((url = unescapeURL(&pathname[FS_URL_OFFSET])) != NULL)
			{
				err=PR_GetFileInfo(url, &fn);
				if (!err)
				{
					switch(fn.type)
					{
						case	PR_FILE_FILE:
#ifdef	XP_MAC
						if (!nativeMacPathname(pathname, &fss))
						{
							if (!FSpGetFInfo(&fss, &fndrInfo))
							{
								if (fndrInfo.fdFlags & kIsAlias)
								{
									/* XXX localization */
									retVal = copyString("Alias");
								}
							}
						}
#endif
						if (retVal == NULL)
						{
							retVal = (void *)copyString(XP_GetString(RDF_FILE_DESC_STR));
						}
						break;

						case	PR_FILE_DIRECTORY:
#ifdef	XP_MAC
						if (!nativeMacPathname(pathname, &fss))
						{
							if ((fss.parID == 0) || (fss.parID == 1))
							{
								retVal = copyString(XP_GetString(RDF_VOLUME_DESC_STR));
							}
						}
#endif
						if (retVal == NULL)
						{
							retVal = (void *)copyString(XP_GetString(RDF_DIRECTORY_DESC_STR));
						}
						break;
					}
				}
				XP_FREE(url);
			}
		}
	}
	else if ((s == gWebData->RDF_lastModifiedDate) && (tv))
	{
		if ((pathname = resourceID(u)) != NULL)
		{
			if ((url = unescapeURL(&pathname[FS_URL_OFFSET])) != NULL)
			{
				err = PR_GetFileInfo(url, &fn);
				if (!err)
				{
					LL_I2L(oneMillion, PR_USEC_PER_SEC);
					LL_DIV(dateVal, fn.modifyTime, oneMillion);
					LL_L2I(modifyTime, dateVal);
					if (type == RDF_STRING_TYPE)
					{
						if ((time = localtime((time_t *) &modifyTime)) != NULL)
						{
#ifdef	XP_MAC
							time->tm_year += 4;
							strftime(buffer, sizeof(buffer), XP_GetString(RDF_HTML_MACDATE), time);
#elif	XP_UNIX
							strftime(buffer, sizeof(buffer), XP_GetString(RDF_HTML_MACDATE), time);
#else
							strftime(buffer, sizeof(buffer), XP_GetString(RDF_HTML_WINDATE), time);
#endif
							retVal = copyString(buffer);
						}
					}
					else if (type == RDF_INT_TYPE)
					{
						retVal = (void *)modifyTime;
					}
				}
				XP_FREE(url);
			}
		}
	}
	else if ((s == gWebData->RDF_creationDate) && (tv))
	{
		if ((pathname = resourceID(u)) != NULL)
		{
			if ((url = unescapeURL(&pathname[FS_URL_OFFSET])) != NULL)
			{
				err = PR_GetFileInfo(url, &fn);
				if (!err)
				{
					LL_I2L(oneMillion, PR_USEC_PER_SEC);
					LL_DIV(dateVal, fn.creationTime, oneMillion);
					LL_L2I(creationTime, dateVal);
					if (type == RDF_STRING_TYPE)
					{
						if ((time = localtime((time_t *) &creationTime)) != NULL)
						{
#ifdef	XP_MAC
							time->tm_year += 4;
							strftime(buffer, sizeof(buffer), XP_GetString(RDF_HTML_MACDATE), time);
#elif	XP_UNIX
							strftime(buffer, sizeof(buffer), XP_GetString(RDF_HTML_MACDATE), time);
#else
							strftime(buffer, sizeof(buffer), XP_GetString(RDF_HTML_WINDATE), time);
#endif
							retVal = copyString(buffer);
						}
					}
					else if (type == RDF_INT_TYPE)
					{
						retVal = (void *)creationTime;
					}
				}
				XP_FREE(url);
			}
		}
	}
	return(retVal);
}



PRBool
fileDirectoryp(RDF_Resource u)
{
	PRFileInfo	info;
	PRBool		retVal = PR_FALSE;
	PRStatus	err;
	char		*pathname, *url;

	if (startsWith("file:",  resourceID(u)))
	{
		if ((pathname = resourceID(u)) != NULL)
		{
			if ((url = unescapeURL(&pathname[FS_URL_OFFSET])) != NULL)
			{
				if ((err=PR_GetFileInfo(url, &info)) == PR_SUCCESS)
				{
					if (info.type == PR_FILE_DIRECTORY)
					{
						retVal = PR_TRUE;
					}
				}
				XP_FREE(url);
			}
		}
	}
	return(retVal);
}



RDF_Cursor
fsGetSlotValues (RDFT rdf, RDF_Resource u, RDF_Resource s,
		RDF_ValueType type,  PRBool inversep, PRBool tv)
{
	PRDir			*d = NULL;
	RDF_Cursor		c = NULL;

	if ((((s == gCoreVocab->RDF_child) && (!inversep)) || ((s == gCoreVocab->RDF_parent) && (inversep))) &&
		(type == RDF_RESOURCE_TYPE) && (tv))
	{
		if ((c = getMem(sizeof(struct RDF_CursorStruct))) != NULL)
		{
			if (u == gNavCenter->RDF_LocalFiles)
			{
				c->u = u;
				c->s = s;
				c->type = type;
				c->count = 0;
				c->pdata = NULL;
			}
			else if (startsWith("file://", resourceID(u)))
			{
				if ((d = OpenDir(resourceID(u))) != NULL)
				{
					c->u = u;
					c->s = s;
					c->type = type;
					c->count = PR_SKIP_BOTH;
					c->pdata = d;
				}
				else
				{
					freeMem(c);
					c = NULL;
				}
			}
			else
			{
				freeMem(c);
				c = NULL;
			}
		}
	}
	return(c);
}



PRBool
isFileVisible(char *fileURL)
{
	PRBool			retVal = PR_TRUE;
#ifdef	XP_MAC
	FInfo			fndrInfo;
	FSSpec			fss;
	OSErr			err;
#endif
#ifdef	XP_WIN
	char			*p;
#endif

#ifdef	XP_MAC
	if (!(err=nativeMacPathname(fileURL, &fss)))
	{
		if (!(err = FSpGetFInfo(&fss, &fndrInfo)))
		{
			if (fndrInfo.fdFlags & kIsInvisible)
			{
				retVal = PR_FALSE;
			}
		}
	}
#endif

#ifdef	XP_WIN
	if ((p = strrchr(fileURL, '/')) != NULL)
	{
		++p;
		if ((!strcmp(p, ".")) || (!strcmp(p, "..")))
		{
			retVal = PR_FALSE;
		}
	}
#endif

	return(retVal);
}



void *
fsNextValue (RDFT rdf, RDF_Cursor c)
{
	PRBool			isDirectoryFlag = false, sep;
	PRDirEntry		*de;
	PRFileInfo		fn;
	RDF_Resource		vol;
	char			*base, *encoded = NULL, *url, *url2;
	void			*retVal = NULL;

	XP_ASSERT(c != NULL);
	if (c == NULL)				return(NULL);
	if (c->type != RDF_RESOURCE_TYPE)	return(NULL);

	if (c->u == gNavCenter->RDF_LocalFiles)
	{
		do
		{
			if ((url = getVolume(c->count++, PR_FALSE)) != NULL)
			{
				if ((vol = RDF_GetResource(NULL, url, 1)) != NULL)
				{
					setContainerp(vol, 1);
					setResourceType(vol, LFS_RT);
					retVal = (void *)vol;
				}
				XP_FREE(url);
			}
		} while((retVal == NULL) && (c->count <= 26));
	}
	else if (c->pdata != NULL)
	{
		while ((de = PR_ReadDir((PRDir*)c->pdata, (PRDirFlags)(c->count++))) != NULL)
		{
			if ((base = NET_Escape(de->name, URL_XALPHAS)) != NULL)		/* URL_PATH */
			{
				sep = ((resourceID(c->u))[strlen(resourceID(c->u))-1] == XP_DIRECTORY_SEPARATOR);
				if (sep)
				{
					url = PR_smprintf("%s%s",  resourceID(c->u), base);
				}
				else
				{
					url = PR_smprintf("%s/%s",  resourceID(c->u), base);
				}
				XP_FREE(base);

				if (url != NULL)
				{
					encoded = unescapeURL(&url[FS_URL_OFFSET]);
					if (encoded != NULL)
					{
#ifdef  XP_WIN
						if (encoded[1] == '|') encoded[1] = ':';
#endif
						PR_GetFileInfo(encoded, &fn);
						if (fn.type == PR_FILE_DIRECTORY)
						{
							isDirectoryFlag = TRUE;
							url2 = PR_smprintf("%s/", url);
							XP_FREE(url);
							url = url2;
						}
						freeMem(encoded);
					}
					if (isFileVisible(url) == PR_FALSE)
					{
						XP_FREE(url);
						url = NULL;
					}
					if (url != NULL)
					{
						retVal = (void *)CreateFSUnit(url, isDirectoryFlag);
						XP_FREE(url);
						break;
					}
				}
			}

		}
		if (de == NULL)
		{
			PR_CloseDir((PRDir*)c->pdata);
			c->pdata = NULL;
		}
	}
	return(retVal);
}



RDF_Error
fsDisposeCursor (RDFT rdf, RDF_Cursor c)
{
	XP_ASSERT(c != NULL);

	if (c != NULL)
	{
		if (c->pdata != NULL)
		{
			PR_CloseDir((PRDir*)c->pdata);
			c->pdata = NULL;
		}
		freeMem(c);
	}
	return 0;
}



RDF_Resource
CreateFSUnit (char *nname, PRBool isDirectoryFlag)
{
	RDF_Resource		r = NULL;

	if (startsWith("file:///", nname))
	{
		if ((r =(RDF_Resource)PL_HashTableLookup(resourceHash, nname)) == NULL)
		{
			if ((r = NewRDFResource(nname)) != NULL)
			{
				setResourceType(r, LFS_RT);
				setContainerp(r, isDirectoryFlag);
			}
		}	
	}
	return(r);
} 
