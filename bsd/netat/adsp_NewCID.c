/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
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
 * dspNewCID.c 
 *
 * From v01.04 04/20/90 mbs
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
 * dspNewCID
 * 
 * INPUTS:
 * 	--> ccbRefNum		refnum of connection end
 *
 * OUTPUTS:
 *	<-- newCID		new connection identifier
 *
 * ERRORS:
 *	errRefNum		bad connection refnum
 *	errState		connection is not closed
 */
int adspNewCID(sp, pb)		/* (DSPPBPtr pb) */
    CCBPtr		sp;
    struct adspcmd *pb;
{
    if (sp == 0) {
	pb->ioResult = errRefNum;
	return EINVAL;
    }

    if (sp->state != sClosed) {	/* Can only assign to a closed connection */
	pb->ioResult = errState;
	return EINVAL;
    }

    /*
     * Assign a unique connection ID to this ccb
     */
    sp->locCID = pb->u.newCIDParams.newcid = NextCID();

    pb->ioResult = 0;
    adspioc_ack(0, pb->ioc, pb->gref);
    return 0;
}
