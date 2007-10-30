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
 * dspAttention.c 
 *
 * From Mike Shoemaker v01.05  03/16/90 mbs
 */
/*
 * Change log:
 *   06/29/95 - Modified to handle flow control for writing (Tuyen Nguyen)
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
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

/*
 * dspAttention
 * 
 * INPUTS:
 * 	--> ccbRefNum		refnum of connection end
 *	--> attnCode		client attention code
 *	--> attnSize		size in bytes of attention data
 *	--> attnData		pointer to attention data
 *	--> attnInterval	attention retransmit interval 
 *				(ignored by ADSP 1.5 & up)
 *
 * OUTPUTS:
 *	none
 *
 * ERRORS:
 *	errRefNum		bad connection refnum
 *	errState		connection is not open
 *	errAttention		attention message too long
 *	errAborted		request aborted by Remove or Close call
 */
int adspAttention(register struct adspcmd *pb, register CCBPtr sp)
{
    int	s;
    register gbuf_t *mp, *nmp;
    unsigned char uerr;
	
    if (sp == 0) {
	pb->ioResult = errRefNum;
	return EINVAL;
    }
	
    if (sp->state != sOpen) {	/* If we're not open, tell user to go away */
	pb->ioResult = errState;
	uerr = ENOTCONN;
l_err:
	atalk_notify(sp->gref, uerr);
	gbuf_freem(pb->mp);
	return 0;
    }
	
    if (pb->u.attnParams.attnSize > attnBufSize) /* If data too big, bye-bye */
    {
	pb->ioResult = errAttention;
	uerr = ERANGE;
	goto l_err;
    }

    /* The 1st mbuf in the pb->mp chain (mp) is the adspcmd structure. 
       The 2nd mbuf (nmp) will be the beginning of the data. */
    mp = pb->mp;
    if (pb->u.attnParams.attnSize) {
        nmp = gbuf_cont(mp);
	if (gbuf_len(mp) > sizeof(struct adspcmd)) {
	    if ((nmp = gbuf_dupb(mp)) == 0) {
		gbuf_wset(mp, sizeof(struct adspcmd));
		uerr = ENOBUFS;
		goto l_err;
	    }
	    gbuf_wset(mp, sizeof(struct adspcmd));
	    gbuf_rinc(nmp, sizeof(struct adspcmd));
	    gbuf_cont(nmp) = gbuf_cont(mp);
	    gbuf_cont(mp) = nmp;
	}
    }
    pb->ioDirection = 1;	/* outgoing attention data */
    ATDISABLE(s, sp->lock);
    if (sp->sapb) {		/* Pending attentions already? */
	qAddToEnd(&sp->sapb, pb); /* Just add to end of queue */
	ATENABLE(s, sp->lock);
    } else {
	sp->sendAttnData = 1;	/* Start off this attention */
	pb->qLink = 0;
	sp->sapb = pb;
	ATENABLE(s, sp->lock);
	CheckSend(sp);
    }
    pb->ioResult = 1;	/* indicate that the IO is not complete */
    return 0;
}
