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

/*
** File:            concur.c 
** Description:     test of adding and removing concurrency options
*/

#include "prcvar.h"
#include "prinit.h"
#include "prinrval.h"
#include "prlock.h"
#include "prprf.h"

#include "plgetopt.h"

#if defined(XP_MAC)
#include "pprio.h"
#else
#include "private/pprio.h"
#endif

#include <stdlib.h>

#define DEFAULT_RANGE 20
#define DEFAULT_LOOPS 100

static PRThreadScope thread_scope = PR_LOCAL_THREAD;

typedef struct Context
{
    PRLock *ml;
    PRCondVar *cv;
    PRIntn want, have;
} Context;


/*
** Make the instance of 'context' static (not on the stack)
** for Win16 threads
*/
static Context context = {NULL, NULL, 0, 0};

static void PR_CALLBACK Dull(void *arg)
{
    Context *context = (Context*)arg;
    PR_Lock(context->ml);
    context->have += 1;
    while (context->want >= context->have)
        PR_WaitCondVar(context->cv, PR_INTERVAL_NO_TIMEOUT);
    context->have -= 1;
    PR_Unlock(context->ml);
}  /* Dull */

PRIntn PR_CALLBACK Concur(PRIntn argc, char **argv)
{
    PRUintn cpus;
	PLOptStatus os;
    PRBool debug = PR_FALSE;
    PRUintn range = DEFAULT_RANGE;
    PRUintn loops = DEFAULT_LOOPS;
	PRIntervalTime hundredMills = PR_MillisecondsToInterval(100);
	PLOptState *opt = PL_CreateOptState(argc, argv, "Gdl:r:");
	while (PL_OPT_EOL != (os = PL_GetNextOpt(opt)))
    {
		if (PL_OPT_BAD == os) continue;
        switch (opt->option)
        {
        case 'G':  /* GLOBAL threads */
			thread_scope = PR_GLOBAL_THREAD;
            break;
        case 'd':  /* debug mode */
			debug = PR_TRUE;
            break;
        case 'r':  /* range limit */
			range = atoi(opt->value);
            break;
        case 'l':  /* loop counter */
			loops = atoi(opt->value);
            break;
         default:
            break;
        }
    }
	PL_DestroyOptState(opt);

    if (0 == range) range = DEFAULT_RANGE;
    if (0 == loops) loops = DEFAULT_LOOPS;

    context.ml = PR_NewLock();
    context.cv = PR_NewCondVar(context.ml);

    if (debug)
        PR_fprintf(
            PR_STDERR, "Testing with %d CPUs and %d interations\n", range, loops);

    while (--loops > 0)
    {
        for (cpus = 1; cpus < range; ++cpus)
        {
            PR_SetConcurrency(cpus);
            context.want = cpus;

            (void)PR_CreateThread(
                PR_USER_THREAD, Dull, &context, PR_PRIORITY_NORMAL,
				      thread_scope, PR_UNJOINABLE_THREAD, 0);
        }

        PR_Sleep(hundredMills);

        for (cpus = range; cpus > 0; cpus--)
        {
            PR_SetConcurrency(cpus);
            context.want = cpus - 1;

            PR_Lock(context.ml);
            PR_NotifyCondVar(context.cv);
            PR_Unlock(context.ml);
        }
    }

    
    if (debug)
        PR_fprintf(
            PR_STDERR, "Waiting for %d thread(s) to exit\n", context.have);

    while (context.have > 0) PR_Sleep(hundredMills);

    if (debug)
        PR_fprintf(
            PR_STDERR, "Finished [want: %d, have: %d]\n",
            context.want, context.have);

    PR_DestroyLock(context.ml);
    PR_DestroyCondVar(context.cv);

    PR_fprintf(PR_STDERR, "PASSED\n");

    return 0;
} /* Concur */

PRIntn main(PRIntn argc, char **argv)
{
    PR_STDIO_INIT();
    return PR_Initialize(Concur, argc, argv, 0);
}  /* main */

/* concur.c */
