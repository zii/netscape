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

#include "primpl.h"

#include <string.h>
#include <fcntl.h>

#ifdef XP_UNIX
#ifdef AIX
/* To pick up sysconf */
#include <unistd.h>
#else
/* To pick up getrlimit, setrlimit */
#include <sys/time.h>
#include <sys/resource.h>
#endif
#endif /* XP_UNIX */

extern PRLock *_pr_flock_lock;

static PRInt32 PR_CALLBACK FileRead(PRFileDesc *fd, void *buf, PRInt32 amount)
{
    PRInt32 rv = 0;
    PRThread *me = _PR_MD_CURRENT_THREAD();

    if (_PR_PENDING_INTERRUPT(me)) {
 		me->flags &= ~_PR_INTERRUPT;
		PR_SetError(PR_PENDING_INTERRUPT_ERROR, 0);
		rv = -1;
    }
    if (_PR_IO_PENDING(me)) {
        PR_SetError(PR_IO_PENDING_ERROR, 0);
	rv = -1;
    }
    if (rv == -1)
    	return rv;

	rv = _PR_MD_READ(fd, buf, amount);
	if (rv < 0) {
		PR_ASSERT(rv == -1);
	}
    PR_LOG(_pr_io_lm, PR_LOG_MAX, ("read -> %d", rv));
    return rv;
}

static PRInt32 PR_CALLBACK FileWrite(PRFileDesc *fd, const void *buf, PRInt32 amount)
{
    PRInt32 rv = 0;
    PRInt32 temp, count;
    PRThread *me = _PR_MD_CURRENT_THREAD();

    if (_PR_PENDING_INTERRUPT(me)) {
        me->flags &= ~_PR_INTERRUPT;
        PR_SetError(PR_PENDING_INTERRUPT_ERROR, 0);
	rv = -1;
    }
    if (_PR_IO_PENDING(me)) {
        PR_SetError(PR_IO_PENDING_ERROR, 0);
	rv = -1;
    }
    if (rv != 0)
    	return rv;

    count = 0;
    while (amount > 0) {
		temp = _PR_MD_WRITE(fd, buf, amount);
		if (temp < 0) {
			count = -1;
			break;
		}
		count += temp;
		if (fd->secret->nonblocking) {
			break;
		}
		buf = (const void*) ((const char*)buf + temp);
		amount -= temp;
    }
    PR_LOG(_pr_io_lm, PR_LOG_MAX, ("write -> %d", count));
    return count;
}

static PRInt32 PR_CALLBACK FileSeek(PRFileDesc *fd, PRInt32 offset, PRSeekWhence whence)
{
    PRInt32 result;

    result = _PR_MD_LSEEK(fd, offset, whence);
    return result;
}

static PRInt64 PR_CALLBACK FileSeek64(PRFileDesc *fd, PRInt64 offset, PRSeekWhence whence)
{
    PRInt64 result;

    result = _PR_MD_LSEEK64(fd, offset, whence);
    return result;
}

static PRInt32 PR_CALLBACK FileAvailable(PRFileDesc *fd)
{
    PRInt32 result, cur, end;

    cur = _PR_MD_LSEEK(fd, 0, PR_SEEK_CUR);

	if (cur >= 0)
    	end = _PR_MD_LSEEK(fd, 0, PR_SEEK_END);

    if ((cur < 0) || (end < 0)) {
        return -1;
    }

    result = end - cur;
    _PR_MD_LSEEK(fd, cur, PR_SEEK_SET);

    return result;
}

static PRInt64 PR_CALLBACK FileAvailable64(PRFileDesc *fd)
{
    PRInt64 result, cur, end;
    PRInt64 minus_one;

    LL_I2L(minus_one, -1);
    cur = _PR_MD_LSEEK64(fd, LL_ZERO, PR_SEEK_CUR);

    if (LL_GE_ZERO(cur))
    	end = _PR_MD_LSEEK64(fd, LL_ZERO, PR_SEEK_END);

    if (!LL_GE_ZERO(cur) || !LL_GE_ZERO(end)) return minus_one;

    LL_SUB(result, end, cur);
    (void)_PR_MD_LSEEK64(fd, cur, PR_SEEK_SET);

    return result;
}

static PRStatus PR_CALLBACK FileInfo(PRFileDesc *fd, PRFileInfo *info)
{
	PRInt32 rv;

    rv = _PR_MD_GETOPENFILEINFO(fd, info);
    if (rv < 0) {
	return PR_FAILURE;
    } else
	return PR_SUCCESS;
}

static PRStatus PR_CALLBACK FileInfo64(PRFileDesc *fd, PRFileInfo64 *info)
{
    /* $$$$ NOT YET IMPLEMENTED */
	PRInt32 rv;

    rv = _PR_MD_GETOPENFILEINFO64(fd, info);
    if (rv < 0) return PR_FAILURE;
    else return PR_SUCCESS;
}

static PRStatus PR_CALLBACK FileSync(PRFileDesc *fd)
{
    PRInt32 result;
    result = _PR_MD_FSYNC(fd);
    if (result < 0) {
		return PR_FAILURE;
    }
    return PR_SUCCESS;
}

static PRStatus PR_CALLBACK FileClose(PRFileDesc *fd)
{
    PRInt32 rv;

    if (!fd || fd->secret->state != _PR_FILEDESC_OPEN) {
        PR_SetError(PR_BAD_DESCRIPTOR_ERROR, 0);
        return PR_FAILURE;
    }

    fd->secret->state = _PR_FILEDESC_CLOSED;

    rv =  _PR_MD_CLOSE_FILE(fd->secret->md.osfd);
    PR_FreeFileDesc(fd);
    if (rv < 0) {
        return PR_FAILURE;
    } else {
        return PR_SUCCESS;
    }
}

static PRInt16 PR_CALLBACK FilePoll(
    PRFileDesc *fd, PRInt16 in_flags, PRInt16 *out_flags)
{
    *out_flags = 0;
    return in_flags;
}  /* FilePoll */

PRIOMethods _pr_fileMethods = {
    PR_DESC_FILE,
    FileClose,
    FileRead,
    FileWrite,
    FileAvailable,
    FileAvailable64,
    FileSync,
    FileSeek,
    FileSeek64,
    FileInfo,
    FileInfo64,
    (PRWritevFN)_PR_InvalidInt,		
    (PRConnectFN)_PR_InvalidStatus,		
    (PRAcceptFN)_PR_InvalidDesc,		
    (PRBindFN)_PR_InvalidStatus,		
    (PRListenFN)_PR_InvalidStatus,		
    (PRShutdownFN)_PR_InvalidStatus,	
    (PRRecvFN)_PR_InvalidInt,		
    (PRSendFN)_PR_InvalidInt,		
    (PRRecvfromFN)_PR_InvalidInt,	
    (PRSendtoFN)_PR_InvalidInt,		
    FilePoll,         
    (PRAcceptreadFN)_PR_InvalidInt,   
    (PRTransmitfileFN)_PR_InvalidInt, 
    (PRGetsocknameFN)_PR_InvalidStatus,	
    (PRGetpeernameFN)_PR_InvalidStatus,	
    (PRGetsockoptFN)_PR_InvalidStatus,	
    (PRSetsockoptFN)_PR_InvalidStatus,	
    (PRGetsocketoptionFN)_PR_InvalidStatus,	
    (PRSetsocketoptionFN)_PR_InvalidStatus,	
};

PR_IMPLEMENT(const PRIOMethods*) PR_GetFileMethods(void)
{
    return &_pr_fileMethods;
}

PR_IMPLEMENT(PRFileDesc*) PR_Open(const char *name, PRIntn flags, PRIntn mode)
{
    PRInt32 osfd;
    PRFileDesc *fd = 0;

	if (!_pr_initialized) _PR_ImplicitInitialization();

    /* Map pr open flags and mode to os specific flags */

    osfd = _PR_MD_OPEN(name, flags, mode);
    if (osfd != -1) {
	fd = PR_AllocFileDesc(osfd, &_pr_fileMethods);
        if (!fd) {
            (void) _PR_MD_CLOSE_FILE(osfd);
        }
    }
    return fd;
}

PRInt32 PR_GetSysfdTableMax(void)
{
#if defined(XP_UNIX) && !defined(AIX)
    struct rlimit rlim;

    if ( getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
       /* XXX need to call PR_SetError() */
       return -1;
    }

    return rlim.rlim_max;
#elif defined(AIX)
    return sysconf(_SC_OPEN_MAX);
#elif defined(WIN32) || defined(OS2)
    /*
     * There is a systemwide limit of 65536 user handles.
     * Not sure on OS/2, but sounds good.
     */
    return 16384;
#elif defined (WIN16)
    return FOPEN_MAX;
#elif defined (XP_MAC)
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
   return -1;
#else
    write me;
#endif
}

PRInt32 PR_SetSysfdTableSize(int table_size)
{
#if defined(XP_UNIX) && !defined(AIX)
    struct rlimit rlim;
    PRInt32 tableMax = PR_GetSysfdTableMax();

    if (tableMax < 0) 
        return -1;

    if (tableMax > FD_SETSIZE)
        tableMax = FD_SETSIZE;

    rlim.rlim_max = tableMax;

    /* Grow as much as we can; even if too big */
    if ( rlim.rlim_max < table_size )
        rlim.rlim_cur = rlim.rlim_max;
    else
        rlim.rlim_cur = table_size;

    if ( setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
        /* XXX need to call PR_SetError() */
        return -1;
    }

    return rlim.rlim_cur;
#elif defined(AIX) || defined(WIN32) || defined(WIN16) || defined(OS2)
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    return -1;
#elif defined (XP_MAC)
#pragma unused (table_size)
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
   return -1;
#else
    write me;
#endif
}

PR_IMPLEMENT(PRStatus) PR_Delete(const char *name)
{
	PRInt32 rv;

	rv = _PR_MD_DELETE(name);
	if (rv < 0) {
		return PR_FAILURE;
	} else
		return PR_SUCCESS;
}

PR_IMPLEMENT(PRStatus) PR_GetFileInfo(const char *fn, PRFileInfo *info)
{
	PRInt32 rv;

	rv = _PR_MD_GETFILEINFO(fn, info);
	if (rv < 0) {
		return PR_FAILURE;
	} else
		return PR_SUCCESS;
}

PR_IMPLEMENT(PRStatus) PR_GetFileInfo64(const char *fn, PRFileInfo64 *info)
{
    PRInt32 rv;

    rv = _PR_MD_GETFILEINFO64(fn, info);
    if (rv < 0) {
        return PR_FAILURE;
    } else {
        return PR_SUCCESS;
    }
}

PR_IMPLEMENT(PRStatus) PR_Rename(const char *from, const char *to)
{
	PRInt32 rv;

	rv = _PR_MD_RENAME(from, to);
	if (rv < 0) {
		return PR_FAILURE;
	} else
		return PR_SUCCESS;
}

PR_IMPLEMENT(PRStatus) PR_Access(const char *name, PRAccessHow how)
{
PRInt32 rv;

	rv = _PR_MD_ACCESS(name, how);
	if (rv < 0) {
		return PR_FAILURE;
	} else
		return PR_SUCCESS;
}

/*
** Import an existing OS file to NSPR 
*/
PR_IMPLEMENT(PRFileDesc*) PR_ImportFile(PRInt32 osfd)
{
    PRFileDesc *fd = NULL;

    fd = PR_AllocFileDesc(osfd, &_pr_fileMethods);
    if( !fd ) {
        (void) _PR_MD_CLOSE_FILE(osfd);
    }

    return fd;
}

#ifndef NO_NSPR_10_SUPPORT
/*
** PR_Stat() for Win16 is defined in w16io.c
** it is a hack to circumvent problems in Gromit and Java
** See also: BugSplat: 98516.
*/
#if !defined(WIN16)
/*
 * This function is supposed to be for backward compatibility with
 * nspr 1.0.  Therefore, it still uses the nspr 1.0 error-reporting
 * mechanism -- returns a PRInt32, which is the error code when the call
 * fails.
 * 
 * If we need this function in nspr 2.0, it should be changed to
 * return PRStatus, as follows:
 *
 * PR_IMPLEMENT(PRStatus) PR_Stat(const char *name, struct stat *buf)
 * {
 *     PRInt32 rv;
 *
 *     rv = _PR_MD_STAT(name, buf);
 *     if (rv < 0)
 *         return PR_FAILURE;
 *     else
 *         return PR_SUCCESS;
 * }
 *
 * -- wtc, 2/14/97.
 */
PR_IMPLEMENT(PRInt32) PR_Stat(const char *name, struct stat *buf)
{
    PRInt32 rv;

    rv = _PR_MD_STAT(name, buf);
	return rv;
}

#endif /* !defined(WIN16)  */
#endif /* ! NO_NSPR_10_SUPPORT */

PR_IMPLEMENT(PRStatus) PR_LockFile(PRFileDesc *fd)
{
    PRStatus rv = PR_SUCCESS;

    PR_Lock(_pr_flock_lock);
    if (fd->secret->lockCount == 0) {
        rv = _PR_MD_LOCKFILE(fd->secret->md.osfd);
        if (rv == PR_SUCCESS)
            fd->secret->lockCount = 1;
    } else {
        fd->secret->lockCount++;
    }
    PR_Unlock(_pr_flock_lock);
 
    return rv;
}

PR_IMPLEMENT(PRStatus) PR_TLockFile(PRFileDesc *fd)
{
    PRStatus rv = PR_SUCCESS;

    PR_Lock(_pr_flock_lock);
    if (fd->secret->lockCount == 0) {
        rv = _PR_MD_TLOCKFILE(fd->secret->md.osfd);
        PR_ASSERT(rv == PR_SUCCESS || fd->secret->lockCount == 0);
        if (rv == PR_SUCCESS)
            fd->secret->lockCount = 1;
    } else {
        fd->secret->lockCount++;
    }
    PR_Unlock(_pr_flock_lock);

    return rv;
}

PR_IMPLEMENT(PRStatus) PR_UnlockFile(PRFileDesc *fd)
{
    PRStatus rv = PR_SUCCESS;

    PR_Lock(_pr_flock_lock);
    if (fd->secret->lockCount == 1) {
        rv = _PR_MD_UNLOCKFILE(fd->secret->md.osfd);
        if (rv == PR_SUCCESS) 
            fd->secret->lockCount = 0;
    } else {
        fd->secret->lockCount--;
    }
    PR_Unlock(_pr_flock_lock);

    return rv;
}

PR_IMPLEMENT(PRStatus) PR_CreatePipe(
    PRFileDesc **readPipe,
    PRFileDesc **writePipe
)
{
#if defined(XP_MAC)
#pragma unused (readPipe, writePipe)
#endif

#ifdef WIN32
    HANDLE readEnd, writeEnd;
    SECURITY_ATTRIBUTES pipeAttributes;

    ZeroMemory(&pipeAttributes, sizeof(pipeAttributes));
    pipeAttributes.nLength = sizeof(pipeAttributes);
    pipeAttributes.bInheritHandle = TRUE;
    if (CreatePipe(&readEnd, &writeEnd, &pipeAttributes, 0) == 0) {
        PR_SetError(PR_UNKNOWN_ERROR, GetLastError());
        return PR_FAILURE;
    }
    *readPipe = PR_AllocFileDesc((PRInt32)readEnd, &_pr_fileMethods);
    if (NULL == *readPipe) {
        CloseHandle(readEnd);
        CloseHandle(writeEnd);
        return PR_FAILURE;
    }
    *writePipe = PR_AllocFileDesc((PRInt32)writeEnd, &_pr_fileMethods);
    if (NULL == *writePipe) {
        PR_Close(*readPipe);
        CloseHandle(writeEnd);
        return PR_FAILURE;
    }
#ifdef WINNT
    (*readPipe)->secret->md.nonoverlapped = PR_TRUE;
    (*writePipe)->secret->md.nonoverlapped = PR_TRUE;
#endif
    return PR_SUCCESS;
#elif defined(XP_UNIX)
    int pipefd[2];

    if (pipe(pipefd) == -1) {
        /* XXX map pipe error */
        PR_SetError(PR_UNKNOWN_ERROR, errno);
        return PR_FAILURE;
    }
    *readPipe = PR_AllocFileDesc(pipefd[0], &_pr_fileMethods);
    if (NULL == *readPipe) {
        close(pipefd[0]);
        close(pipefd[1]);
        return PR_FAILURE;
    }
    *writePipe = PR_AllocFileDesc(pipefd[1], &_pr_fileMethods);
    if (NULL == *writePipe) {
        PR_Close(*readPipe);
        close(pipefd[1]);
        return PR_FAILURE;
    }
    _MD_MakeNonblock(*readPipe);
    _MD_MakeNonblock(*writePipe);
    return PR_SUCCESS;
#else
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    return PR_FAILURE;
#endif
}
