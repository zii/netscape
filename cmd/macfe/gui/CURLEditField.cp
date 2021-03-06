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

// ΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡ
//	CURLEditField.cp
// ΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡ

#include "CURLEditField.h"

#include <UDrawingState.h>

#include <stdio.h>

#include "net.h"	// for URL_Struct

#include "CNSContext.h"	// for CNSContext messages
#include "ufilemgr.h" // for CFileMgr::FileNameFromURL

#include "libmocha.h" // for LM_StripWysiwygURLPrefix

const size_t cCompareWholeString = 0;

struct urlFilter {
	const char*	string;
	size_t		comparisonLength;
};

// table of URL's not to display
const Uint8 numFilteredURLs = 3;
const urlFilter cAboutFilter = { "about:document", cCompareWholeString	};
const urlFilter cMailtoFilter = { "mailto:",	7	};
const urlFilter cNetHelpFilter = { "nethelp:",	8	};
const urlFilter* filteredURLs[] =
{
	&cAboutFilter,
	&cMailtoFilter,
	&cNetHelpFilter
};

CURLEditField::CURLEditField(LStream *inStream) :
CTSMEditField(inStream), mURLStringInSync(false)
{
}

Boolean CURLEditField::HandleKeyPress(const EventRecord& inKeyEvent)
{
	char		c = inKeyEvent.message & charCodeMask;
	Boolean		handled = false;
	
	if ((c == char_Enter) || (c == char_Return))
	{
		Int32	blockSize = 1024;				// 1024 is max len of field in PPob
		char	*urlBlock = (char *)XP_ALLOC(blockSize);
		ThrowIfNil_(urlBlock);
		GetDescriptor(urlBlock, blockSize);
		BroadcastMessage(msg_UserSubmittedURL, urlBlock);
		XP_FREE(urlBlock);
		handled = true;
	}
	else
	{
		handled = CTSMEditField::HandleKeyPress(inKeyEvent);
		if (handled)
		{
			if ((c != char_Tab) && mURLStringInSync)
			{
				BroadcastMessage(msg_UserChangedURL);
				mURLStringInSync = false;
			}
		}
	}
	return handled;
}

void CURLEditField::DrawSelf()
{
	StColorPenState::Normalize();

	Rect theFrame;
	CalcLocalFrameRect(theFrame);
	::EraseRect(&theFrame);

	CTSMEditField::DrawSelf();
}

void CURLEditField::ClickSelf(const SMouseDownEvent& inMouseDown)
{
	Boolean	wasTarget = IsTarget();
	
	if (wasTarget && GetClickCount() == 3)
		SelectAll();
	else
	{
		CTSMEditField::ClickSelf(inMouseDown);
		
		// If we just switched the target to ourselves and the user
		// didn't just make a partial selection of the text,
		// then we select the entire field for convenience.
		//
		if (!wasTarget && IsTarget())
		{
			TEHandle	textEditHandle = GetMacTEH();
			
			if ( (**textEditHandle).selStart == (**textEditHandle).selEnd ) 	 	
				SelectAll();
		}
	}
}


// need these here to keep the C++ compiler happy with the overloads
// below.
void CURLEditField::SetDescriptor(ConstStr255Param inDescriptor)
{
	Inherited::SetDescriptor(inDescriptor);
}

void CURLEditField::GetDescriptor(Str255 outDescriptor)
{
	Inherited::GetDescriptor(outDescriptor);
}


// Needed for strings > 255 chars long
// inDescriptorStorage must have been allocated. It's length is given in ioLength
void CURLEditField::GetDescriptor(char *inDescriptorStorage, Int32 &ioLength)
{
	Int32		curLength;
	
	curLength = (**mTextEditH).teLength;

	if (curLength >= ioLength)
		curLength = ioLength - 1;		// space for terminator
	
	Handle		textHandle = ::TEGetText(mTextEditH);		//the handle is owned by the TE
	
	::BlockMoveData(*textHandle, inDescriptorStorage, curLength);
	inDescriptorStorage[curLength] = '\0';
	ioLength = curLength;	// excludes the terminator, i.e. same as strlen
}


// Needed for strings > 255 chars long
void CURLEditField::SetDescriptor(const char *inDescriptor, Int32 inLength)
{
	Assert_(inLength < mMaxChars);

	if (inLength > mMaxChars)
		inLength = mMaxChars;
		
	::TESetText(inDescriptor, inLength, mTextEditH);
	Refresh();
}


void CURLEditField::ListenToMessage(MessageT inMessage, void* ioParam)
{
	if (ioParam)
	{
		switch (inMessage)
		{
			// NOTE: We assume we only get this broadcast from the main
			// CNSContext
			case msg_NSCStartLoadURL:
			case msg_NSCLayoutNewDocument:
				URL_Struct* theURL = (URL_Struct*)ioParam;
				// 1997-03-23 pkc
				// Call LM_StripWysiwygURLPrefix to strip those pesky
				// "wysiwyg" URL's. According to Brendan, LM_StripWysiwygURLPrefix
				// doesn't allocate a new string.
				const char *urlOffset = LM_StripWysiwygURLPrefix(theURL->address);
				if (DisplayURL(urlOffset))
				{
					SetDescriptor(urlOffset, XP_STRLEN(urlOffset));
					mURLStringInSync = true;
				}
		}
	}
}

// Filter function to determine whether or not to display URL

Boolean CURLEditField::DisplayURL(const char *inURL)
{
	// if inURL is in filteredURLs table, return false
	for(int i = 0; i < numFilteredURLs; i++)
	{
		const urlFilter* filter = filteredURLs[i];
		if (filter->comparisonLength == cCompareWholeString)
		{
			if (XP_STRCMP(filter->string, inURL) == 0)
				return false;
		}
		else
		{
			if (XP_STRNCMP(filter->string, inURL, filter->comparisonLength) == 0)
				return false;
		}
	}
	return true;
}

Boolean CURLEditField::ObeyCommand(CommandT inCommand,void *ioParam)
{
	if (inCommand == msg_TabSelect)
	{
		if (IsVisible())
			return true;
		else
			return false;
	}
	else
	{
		return CTSMEditField::ObeyCommand(inCommand, ioParam);
	}
}

void CURLEditField::BeTarget()
{
	CTSMEditField::BeTarget();
	SelectAll();
}
