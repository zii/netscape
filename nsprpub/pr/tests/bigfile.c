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

#include "prio.h"
#include "prmem.h"
#include "prprf.h"
#include "prinit.h"
#include "prerror.h"
#include "prthread.h"

#include "plerror.h"
#include "plgetopt.h"

#define DEFAULT_COUNT 10
#define DEFAULT_FILESIZE 1
#define BUFFER_SIZE 1000000

typedef enum {v_silent, v_whisper, v_shout} Verbosity;
static void Verbose(Verbosity, const char*, const char*, PRIntn);

#define VERBOSE(_l, _m) Verbose(_l, _m, __FILE__, __LINE__)

static PRIntn filesize = 1;
static PRIntn test_result = 2;
static PRFileDesc *output = NULL;
static PRIntn verbose = v_silent;

static PRIntn Usage(void)
{
    PR_fprintf(output, "Bigfile test usage:\n");
    PR_fprintf(output, ">bigfile [-G] [-d] [-v[*v]] [-s <n>] <filename>\n");
    PR_fprintf(output, "\td\tdebug mode (equivalent to -vvv)\t(false)\n");
    PR_fprintf(output, "\tv\tAdditional levels of output\t(none)\n");
    PR_fprintf(output, "\ts <n>\tFile size in megabytes\t\t(1 megabyte)\n");
    PR_fprintf(output, "\t<filename>\tName of test file\t(none)\n");
    return 2;  /* nothing happened */
}  /* Usage */

static PRStatus DeleteIfFound(const char *filename)
{
    PRStatus rv;
    VERBOSE(v_shout, "Checking for existing file");
    rv = PR_Access(filename, PR_ACCESS_WRITE_OK);
    if (PR_SUCCESS == rv)
    {
        VERBOSE(v_shout, "Deleting existing file");
        rv = PR_Delete(filename);
        if (PR_FAILURE == rv) VERBOSE(v_shout, "Cannot delete big file");
    }
    else if (PR_FILE_NOT_FOUND_ERROR !=  PR_GetError())
        VERBOSE(v_shout, "Cannot access big file");
    return rv;
}  /* DeleteIfFound */

static PRIntn Error(const char *msg, const char *filename)
{
    PRInt32 error = PR_GetError();
    if (NULL != msg)
    {
        if (0 == error) PR_fprintf(output, msg);
        else PL_FPrintError(output, msg);
    }
    (void)DeleteIfFound(filename);
    if (v_shout == verbose) PR_Abort();
    return 1;
}  /* Error */

static void Verbose(
    Verbosity level, const char *msg, const char *file, PRIntn line)
{
    if (level <= verbose)
        PR_fprintf(output, "[%s : %d]: %s\n", file, line, msg);
}  /* Verbose */

PRIntn main(PRIntn argc, char **argv)
{
    PRStatus rv;
    char *buffer;
    PLOptStatus os;
    PRInt32 loop, bytes;
    PRFileDesc *file = NULL;
    const char *filename = NULL;
    PRIntn count = DEFAULT_COUNT;
    PRFileInfo64 *big_info = NULL;
    PRInt64 big_answer, big_size, one_meg, zero_meg, big_fragment;
    PRInt64 filesize64;

    PLOptState *opt = PL_CreateOptState(argc, argv, "dvhs:");

    output = PR_GetSpecialFD(PR_StandardError);
    PR_STDIO_INIT();

    while (PL_OPT_EOL != (os = PL_GetNextOpt(opt)))
    {
        if (PL_OPT_BAD == os) continue;
        switch (opt->option)
        {
        case 0:
            filename = opt->value;
            break;
        case 'd':  /* debug mode */
            verbose = v_shout;
            break;
        case 'v':  /* verbosity */
            if (v_shout > verbose) verbose += 1;
            break;
        case 'c':  /* loop counter */
            count = atoi(opt->value);
            break;
        case 's':  /* filesize */
            filesize = atoi(opt->value);
            break;
        case 'h':  /* confused */
        default:
            return Usage();
        }
    }
    PL_DestroyOptState(opt);

    if (NULL == filename) return Usage();
    if (0 == count) count = DEFAULT_COUNT;
    if (0 == filesize) filesize = DEFAULT_FILESIZE;

    if (PR_FAILURE == DeleteIfFound(filename)) return 1;

    test_result = 0;

    LL_I2L(zero_meg, 0);
    LL_I2L(one_meg, 1000000);
    LL_I2L(filesize64, filesize);
    buffer = (char*)PR_MALLOC(BUFFER_SIZE);
    LL_I2L(big_fragment, BUFFER_SIZE);
    LL_MUL(big_size, filesize64, one_meg); 

    for (loop = 0; loop < BUFFER_SIZE; ++loop) buffer[loop] = (char)loop;

    VERBOSE(v_whisper, "Creating big file");
    file = PR_Open(filename, PR_CREATE_FILE | PR_WRONLY, 0666);
    if (NULL == file) return Error("PR_Open()", filename);
    
    VERBOSE(v_whisper, "Testing available space in empty file");
    big_answer = file->methods->available64(file);
    if (!LL_IS_ZERO(big_answer)) return Error("empty available64()", filename);

#if 0
    VERBOSE(v_whisper, "Filling big file with data");
    while (LL_CMP(big_answer, <, big_size))
    {
        bytes = file->methods->write(file, buffer, BUFFER_SIZE);
        if (bytes != BUFFER_SIZE) return Error("write", filename);
        LL_ADD(big_answer, big_answer, big_fragment);
    }
#else
	LL_SUB(big_size, big_size, one_meg);
	big_answer = file->methods->seek64(file, big_size, PR_SEEK_SET);
	bytes = file->methods->write(file, buffer, BUFFER_SIZE);
    if (bytes != BUFFER_SIZE) return Error("write", filename);
#endif

    VERBOSE(v_whisper, "Testing available space in filled file");
    big_answer = file->methods->available64(file);
    if (LL_NE(big_answer, zero_meg)) return Error("eof available64()", filename);

    VERBOSE(v_whisper, "Rewinding big file");
    big_answer = file->methods->seek64(file, zero_meg, PR_SEEK_SET);
    if (LL_NE(big_answer, zero_meg)) return Error("rewind seek64()", filename);

    VERBOSE(v_whisper, "Establishing available space in rewound file");
    big_size = file->methods->available64(file);
    if (!LL_GE_ZERO(big_size)) return Error("bof available64()", filename);

    VERBOSE(v_whisper, "Closing big file");
    rv = file->methods->close(file);
    if (PR_FAILURE == rv) return Error("close()", filename);

    VERBOSE(v_whisper, "Reopening big file");
    file = PR_Open(filename, PR_RDWR, 0666);
    if (NULL == file) return Error("bof seek64()", filename);

    VERBOSE(v_whisper, "Checking available data in reopened file");
    big_answer = file->methods->available64(file);
    if (LL_NE(big_size, big_answer)) return Error("reopened available64()", filename);

    big_answer = zero_meg;
    VERBOSE(v_whisper, "Rewriting big file data");
    while (LL_CMP(big_answer, <, big_size))
    {
        bytes = file->methods->write(file, buffer, BUFFER_SIZE);
        if (bytes != BUFFER_SIZE) return Error("write", filename);
        LL_ADD(big_answer, big_answer, big_fragment);
    }

    VERBOSE(v_whisper, "Testing available space at eof");
    big_answer = file->methods->available64(file);
    if (LL_NE(big_answer, zero_meg)) return Error("eof available64()", filename);

    VERBOSE(v_whisper, "Rewinding full file file");
    big_answer = file->methods->seek64(file, zero_meg, PR_SEEK_SET);
    if (LL_NE(big_answer, zero_meg)) return Error("bof seek64()", filename);

    VERBOSE(v_whisper, "Testing available space in rewound file");
    big_answer = file->methods->available64(file);
    if (LL_NE(big_answer, big_size)) return Error("bof available64()", filename);

    VERBOSE(v_whisper, "Seeking to end of big file");
    big_answer = file->methods->seek64(file, big_size, PR_SEEK_SET);
    if (LL_NE(big_answer, big_size)) return Error("eof seek64()", filename);

    VERBOSE(v_whisper, "Getting info on big file");
    big_info = PR_NEWZAP(PRFileInfo64);
    rv = file->methods->fileInfo64(file, big_info);
    if (PR_FAILURE == rv) return Error("fileInfo64()", filename);
    PR_DELETE(big_info);

    VERBOSE(v_whisper, "Closing big file");
    rv = file->methods->close(file);
    if (PR_FAILURE == rv) return Error("close()", filename);

    VERBOSE(v_whisper, "Deleting big file");
    rv = PR_Delete(filename);
    if (PR_FAILURE == rv) return Error("PR_Delete()", filename);

    PR_DELETE(buffer);
    return test_result;
} /* main */

/* bigfile.c */
