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
/* dspWrite.c 
 * From Mike Shoemaker v01.13 06/21/90 mbs for MacOS
 */
/*
 * Change log:
 *   06/29/95 - Modified to handle flow control for writing (Tuyen Nguyen)
 *   09/07/95 - Modified for performance (Tuyen Nguyen)
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

void completepb();

/*
 * FillSendQueue
 * 
 * INPUTS:
 * 		sp	stream
 * OUTPUTS:
 * 		none
 */
int FillSendQueue(sp, pb)		/* (CCBPtr sp) */
    register CCBPtr sp;
    register struct adspcmd *pb; /* The write PB we're playing with */
{
	gbuf_t *mb, *nmb;
	int eom;		/* True if should set eom in header */
	int cnt;		/* # of bytes in this write */
	int err = 0;
	int s;

	cnt = pb->u.ioParams.reqCount - pb->u.ioParams.actCount;
	eom = pb->u.ioParams.eom ? F_EOM : 0;

	if (cnt == 0 && eom == 0)	/* Nothing to do here, complete it */
	  	goto unlink;

	/* The 1st mbuf in the pb->mp chain (mb) is the adspcmd structure. 
	   The 2nd mbuf (nmb) will be the beginning of the data. */
	mb = pb->mp;
	nmb = gbuf_cont(mb);
	if (gbuf_len(mb) > sizeof(struct adspcmd)) {
	    if ((nmb = gbuf_dupb(mb)) == 0) {
		gbuf_wset(mb,sizeof(struct adspcmd));
		err = errDSPQueueSize;
		goto unlink;
	    }
	    gbuf_wset(mb,sizeof(struct adspcmd));
	    gbuf_rinc(nmb,sizeof(struct adspcmd));
	    gbuf_cont(nmb) = gbuf_cont(mb);
	} else if (nmb == 0) {
	    if ((nmb = gbuf_alloc(1, PRI_LO)) == 0) {
		err = errENOBUFS;
		goto unlink;
	    }
	}
	gbuf_cont(mb) = 0;

	ATDISABLE(s, sp->lock);
	sp->sData = 1;		/* note that there is data to send */
	if ((mb = sp->csbuf_mb)) {	/* add to the current message */
	    gbuf_linkb(mb, nmb);
	} else
	    sp->csbuf_mb = nmb;	/* mark the buffer we are currently filling */
	if (eom) {
	    if ((mb = sp->sbuf_mb)) {
		while (gbuf_next(mb))
		    mb = gbuf_next(mb);
		gbuf_next(mb) = sp->csbuf_mb; /* add the current item */
	    } else
		sp->sbuf_mb = sp->csbuf_mb;
	    sp->csbuf_mb = 0;	/* if its done, no current buffer */
	}
	pb->u.ioParams.actCount += cnt; /* Update count field in param blk */
	ATENABLE(s, sp->lock);
	
	if (pb->u.ioParams.actCount == pb->u.ioParams.reqCount) {
	    /* Write is complete */
unlink:
	    if (pb->u.ioParams.flush) /* flush the send Q? */
		sp->writeFlush = 1;
		
	    pb->ioResult = err;
	    if (err)
	        atalk_notify(sp->gref, EIO);
	    gbuf_freem(pb->mp);
	}

    return 0;
} /* FillSendQueue */

/*
 * dspWrite
 * 
 * INPUTS:
 * 	-->	ccbRefNum	refnum of connection end
 *	-->	reqCount	requested number of bytes to write
 *	--> 	dataPtr		pointer to buffer for reading bytes into
 *	-->	eom		one if end-of-message, zero otherwise
 *
 * OUTPUTS:
 *	<--	actCount	actual number of bytes written
 *
 * ERRORS:
 *		errRefNum	bad connection refnum
 *		errState	connection is not open
 *		errAborted	request aborted by Remove or Close call
 */
int adspWrite(sp, pb)		/* (DSPPBPtr pb) */
    CCBPtr sp;
    struct adspcmd *pb;
{
    int	s;
	
    if (sp == 0) {
	pb->ioResult = errRefNum;
	return EINVAL;		/* no stream, so drop the message */
    }
	
    ATDISABLE(s, sp->lock);
    if (sp->state != sOpen) {	/* Not allowed */
	pb->ioResult = errState;
	ATENABLE(s, sp->lock);
	atalk_notify(sp->gref, ENOTCONN);
	gbuf_freem(pb->mp);
	return 0;
    }
	
    pb->u.ioParams.actCount = 0; /* Set # of bytes so far to zero */
    ATENABLE(s, sp->lock);
    
    FillSendQueue(sp, pb);	/* Copy from write param block to send queue */

    CheckSend(sp);		/* See if we should send anything */
    return 0;
}

#ifdef notdef
int adsp_check = 1;

CheckQueue(sp)
    CCBPtr sp;
{
    register gbuf_t *mp, *tmp;
    unsigned char current;
    int current_valid = 0;

    if (adsp_check == 0)
	return;
    if (mp = sp->sbuf_mb) {
	current = *mp->b_rptr;
	current_valid = 1;
	while (mp) {
	    tmp = mp;
	    while (tmp) {
		current = CheckData(tmp->b_rptr, tmp->b_wptr - tmp->b_rptr, 
				    current);
		tmp = tmp->b_cont;
	    }
	    mp = mp->b_next;
	}
    }
    if (mp = sp->csbuf_mb) {
	if (current_valid == 0)
	    current = *mp->b_rptr;
	tmp = mp;
	while (tmp) {
	    current = CheckData(tmp->b_rptr, tmp->b_wptr - tmp->b_rptr, 
				    current);
	    tmp = tmp->b_cont;
	}
    }
}


int adsp_bad_block_count;
char *adsp_bad_block;

CheckData(block, size, current)
    char *block;
    int size;
    u_char current;
{
    register int anError = 0;
    register int i;

    for (i = 0; i < size; i++) {
	if ((block[i] & 0xff) != (current & 0xff)) {
	    if (!anError) {
		adsp_bad_block = block;
	    }
	    anError++;
	}
	current++;
    }

    if (anError) {
	adsp_bad_block_count++;
    }
    return current;
}
#endif
