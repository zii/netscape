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

//	CLibMsgThread.cp


#include "CLibMsgThread.h"
#include "msgcom.h"

// ΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡ
//	₯₯₯
//	₯	Class CLibMsgThread
//	₯₯₯
//
//	This is a subclass of LThread which calls the new libmsg init, exit, and
//	idle routines. Since we have to call an idle time routine, it seems like
//	this would be a good candidate as any to be in a thread
// ΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡΡ

CLibMsgThread::CLibMsgThread() :
LThread(false)
{
	MSG_InitMsgLib();
}

CLibMsgThread::~CLibMsgThread()
{
	MSG_ShutdownMsgLib();
}

void *CLibMsgThread::Run()
{
	while(true) {
		LThread::Yield();
		MSG_OnIdle();
		LThread::Yield();
	}
	return NULL;
}