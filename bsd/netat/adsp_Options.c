/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * dspOptions.c 
 * 
 * From v01.06 04/19/90 mbs
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

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

/*
 * dspOptions
 * 
 * INPUTS:
 * 	--> ccbRefNum		refnum of connection end
 *	--> sendBlocking	send blocking threshold
 *	--> sendTimer		send timer interval
 *	--> rtmtTimer		retransmit timer interval
 *	--> badSeqMax		retransmit advice send threshold
 *	--> useCheckSum		generate DDP checksum on internet packets
 *
 * OUTPUTS:
 *	none
 *
 * ERRORS:
 *	errRefNum		bad connection refnum
*/
int adspOptions(sp, pb)	/* (DSPPBPtr pb) */
    CCBPtr		sp;
    struct adspcmd *pb;
{
    short err;
	
    if (sp == 0) {
	pb->ioResult = errRefNum; 
	return EINVAL;
    }
	
    if (pb->u.optionParams.sendBlocking)
	sp->sendBlocking = pb->u.optionParams.sendBlocking;

    if (pb->u.optionParams.sendTimer)
	sp->sendInterval = pb->u.optionParams.sendTimer;

    /* No longer allowed to set retransmit timer as of ADSP 1.5 */
    /* Use it to specify a command blocking request specific to MacOS
     * emulation. */
    if (pb->u.optionParams.rtmtTimer)
    	sp->delay = pb->u.optionParams.rtmtTimer;
    KERNEL_DEBUG(DBG_ADSP_MISC, 0, sp, sp->delay, pb, pb->u.optionParams.rtmtTimer);

    if (pb->u.optionParams.badSeqMax)
	sp->badSeqMax = pb->u.optionParams.badSeqMax;

    sp->useCheckSum = pb->u.optionParams.useCheckSum;
    if (pb->u.optionParams.newPID)
    	sp->pid = pb->u.optionParams.newPID;
    pb->ioResult = 0;
    adspioc_ack(0, pb->ioc, pb->gref);
    return 0;

}
