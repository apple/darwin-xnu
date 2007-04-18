/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* 
 * dspStatus.c 
 * 
 * From Mike Shoemaker v01.04 06/15/90 mbs
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

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

/*
 * calcSendFree
 *
 * INPUTS:
 *		sp		ADSP Stream
 * OUTPUTS:
 *		# of bytes avail in local send queue
 */
int CalcSendQFree(sp)		/* (CCBPtr sp) */
    CCBPtr sp;
{
    int bytes;
    
    bytes = calcSendQ(sp);
    bytes = sp->sbuflen - bytes;

    if (bytes < 0)
	return 0;
    return bytes;
}

calcSendQ(sp)
    CCBPtr sp;
{
    register gbuf_t *mp;
    int bytes = 0;

    if (sp->sData) {		/* There is data in buffer */
	if (mp = sp->sbuf_mb) {
	    do {
		bytes += gbuf_msgsize(mp);
		mp = gbuf_next(mp);
	    } while (mp);
	}
	if (mp = sp->csbuf_mb)
	    bytes += gbuf_msgsize(mp);
    }
    return bytes;
}

/*
 * dspStatus
 * 
 * INPUTS:
 * 	--> ccbRefNum		refnum of connection end
 *
 * OUTPUTS:
 *	<-- statusCCB		Pointer to the connection control block
 *	<-- sendQPending	bytes waiting to be sent or acknowledged
 *	<-- sendQFree		available buffer in bytes of send queue
 *	<-- recvQPending	bytes waiting to be read from queue
 *	<-- recvQFree		available buffer in bytes of receive queue
 *
 * ERRORS:
 *	errRefNum		bad connection refnum
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
int adspStatus(sp, pb)	/* (DSPPBPtr pb) */
    CCBPtr sp;
    register struct adspcmd *pb;
{
    short err;
    short bytes;
    int	s;

    if (sp == 0) {
	pb->ioResult = errRefNum;
	return EINVAL;
    }
	
    pb->u.statusParams.ccbPtr 	= (TPCCB)sp;
    ATDISABLE(s, sp->lock);	
	
    /*
     * pending bytes in send queue
     */		
    if (sp->sData) 
	bytes = calcSendQ(sp);
    else
	bytes = 0;
    pb->u.statusParams.sendQPending = bytes;
	
				/* available buffer space in send queue */
    pb->u.statusParams.sendQFree = CalcSendQFree(sp);
	
    /*
     * pending bytes in recv queue
     */		
    if (sp->rData)
	bytes = calcRecvQ(sp);
    else
	bytes = 0;
    pb->u.statusParams.recvQPending = bytes;
	
				/* available buffer space in receive queue */
    pb->u.statusParams.recvQFree = CalcRecvWdw(sp);

    ATENABLE(s, sp->lock);	
    pb->ioResult = 0;
    adspioc_ack(0, pb->ioc, pb->gref);
    return 0;

}
