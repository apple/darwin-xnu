/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 *	Copyright (c) 1990, 1996-1998 Apple Computer, Inc.
 *	All Rights Reserved.
 */

/* dspInit.c 
 *
 * From Mike Shoemaker v01.20 06/29/90 mbs
 *    Modified for MP, 1996 by Tuyen Nguyen
 *   Modified, April 9, 1997 by Tuyen Nguyen for MacOSX.
 */
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <machine/spl.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>


/*
 * InitContinue
 * 
 * Handle 2nd half of code for dsp init.  We could be called directly by 
 * the dsp Init routine, or if a socket has to be opened, we get called 
 * by the completion routine of the dsp open socket.
 *
 * INPUTS:
 *		sp	The stream we're initing (not yet on list of streams)
 *		pb 	The user's dsp Init param block
 *		soc The socket we're going to use
 * OUTPUTS:
 * 		none
*/
static void InitContinue(sp, pb) /* (CCBPtr sp, DSPPBPtr pb, int soc) */
    CCBPtr sp;
    struct adspcmd *pb;
{

    /* Save connection's socket # in CCB */
    sp->localSocket = pb->socket; 

    /*
     * Link the new ccb onto queue.  Must be done with interrupts off.
     */
    qAddToEnd(AT_ADSP_STREAMS, sp); /* Put on linked list of connections */
    return;
}

/*
 * dspInit
 *
 * Create and initialize a connection end.  return ccbRefNum so that client can
 * reference this ccb in later calls.  The caller provides a pointer to 
 * ccb which belongs to adsp until the connection end is removed.
 *
 * If we have to open a socket, we'll have to do an async open socket, and 
 * finish up in the completion routine
 * 
 * INPUTS:
 * 	--> ccbPtr		Pointer to connection control block
 * 	--> adspcmdPtr		Pointer to user request block
 *
 * OUTPUTS:
 *	<-- ccbRefNum		refnum assigned to this connection.
 *
 * ERRORS:
 *	EADDRINUSE or 0
 */
int adspInit(sp, ap)		/* (DSPPBPtr pb) */
    CCBPtr sp;
    struct adspcmd *ap;
{
    /*
     * Set connection end defaults
     */
    sp->badSeqMax = 3;		/* # of out-of-sequence packets received */
				/* until a retransmit advice packet is sent */
    sp->probeInterval = 6 * 30;	/* 30 second probe interval */
    sp->rtmtInterval = 6 * 5;	/* Just a guess --- 5 seconds */
    sp->sendBlocking = 16;
    sp->sendInterval = 6;
    sp->badSeqMax = 3;		/* This is the default */
	
    sp->ProbeTimer.type	= kProbeTimerType;
    sp->FlushTimer.type = kFlushTimerType;
    sp->RetryTimer.type = kRetryTimerType;
    sp->AttnTimer.type	= kAttnTimerType;
    sp->ResetTimer.type = kResetTimerType;
	
    if (ap->csCode == dspInit) { /* Only do this if not connection Listener */
	/*
	 * Initialize send and receive queue.  Make sure they are the 
	 * right size
	 */
	sp->rbuflen = RecvQSize;
	sp->rbuf_mb = 0;
	sp->sbuflen = SendQSize;
	sp->sbuf_mb = 0;
	sp->csbuf_mb = 0;

	/*
	 * Initialize send and receive defaults
	 */
	
	sp->attn_mb = 0;
	sp->state = sClosed;    /* Set state for connection end */
	/* end dspInit */	    
    } else {  
	
	/* dspCLInit */
	sp->state = sListening;		      /* Set state for conn end */
    }      /* end dspCLInit */
    /*
     * User opens the socket, so continue with the init stuff
     */
    InitContinue(sp, ap);
    return(0);
}


/*
 * AdspBad
 *
 * 
 * INPUTS:
 * 	-->	ap				Parameter block
 *
 */
int AdspBad(ap)			/* (DSPPBPtr pb) */
    struct adspcmd *ap;
{
	dPrintf(D_M_ADSP, D_L_ERROR, 
		("Hey! Do you have the right AuthToolbox?"));
	ap->ioResult = controlErr; /* Unknown csCode in the param block */
	return EINVAL;
}
