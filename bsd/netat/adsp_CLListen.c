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
/* dspCLListen.c 
 * 
 * From Mike Shoemaker v01.02  04/19/90 mbs
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
 * dspCLListen
 * 
 * INPUTS:
 * 	--> ccbRefNum		refnum of connection end
 *	--> filterAddress	filter for incoming open connection requests
 *
 * OUTPUTS:
 *	<-- remoteCID		connection identifier of remote connection end
 *	<-- remoteAddress	internet address of remote connection end
 *	<-- sendSeq		initial send sequence number to use
 *	<-- sendWindow		initial size of remote end's receive buffer
 *	<-- attnSendSeq		initial attention send sequence number to use
 *
 * ERRORS:
 *	errRefNum		bad connection refnum
 *	errState		not a connection listener
 *	errAborted		request aborted by a Remove call
 */
int adspCLListen(sp, pb)	/* (DSPPBPtr pb) */
    register CCBPtr sp;
    register struct adspcmd *pb;
{
    register struct adspcmd *clpb;
    gbuf_t *mp;
    int s;

    if (sp == 0) {
	pb->ioResult = errRefNum;
	return EINVAL;
    }
	
    if (sp->state != sListening) { /* But this isn't a connection listener! */
	pb->ioResult = errState;
	return EALREADY;
    }

    if (mp = gbuf_copym(pb->mp)) {	/* keep a copy of the parameter block */
	    pb->ioResult = 1;	/* not done */
	    adspioc_ack(0, pb->ioc, pb->gref); /* release user ioctl block */
	    clpb = (struct adspcmd *)gbuf_rptr(mp);
	    clpb->ioc = 0;
	    clpb->mp = mp;
	    ATDISABLE(s, sp->lock);
	    if (qAddToEnd(&sp->opb, clpb)){	/* Add to list of listeners */
	     ATENABLE(s, sp->lock);
		return EFAULT; /* bogus, but discriminate from other errors */
	    }
	    ATENABLE(s, sp->lock);
    } else {
	    pb->ioResult = errDSPQueueSize;
	    return ENOBUFS;
    }
    return 0;

}
