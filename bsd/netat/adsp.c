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
 * Change log:
 *   06/29/95 - Modified to handle flow control for writing (Tuyen Nguyen)
 *    Modified for MP, 1996 by Tuyen Nguyen
 *   Modified, April 9, 1997 by Tuyen Nguyen for MacOSX.
 */
#define RESOLVE_DBG
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
#include <netat/ddp.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

#ifdef notdefn
struct adsp_debug adsp_dtable[1025];
int ad_entry = 0;
#endif

extern atlock_t adspgen_lock;

adspAllocateCCB(gref)
    register gref_t *gref;	/* READ queue */
{
    gbuf_t *ccb_mp;
    register CCBPtr sp;

    if (!(ccb_mp = gbuf_alloc(sizeof(CCB), PRI_LO))) {
        return (0);
    }
    bzero((caddr_t) gbuf_rptr(ccb_mp), sizeof(CCB));
    gbuf_wset(ccb_mp,sizeof(CCB));
    gref->info = (caddr_t) ccb_mp;
    sp = (CCBPtr)gbuf_rptr(((gbuf_t *)gref->info));

    sp->pid = gref->pid; /* save the caller process pointer */
    sp->gref = gref;		/* save a back pointer to the WRITE queue */
    sp->sp_mp = ccb_mp;		/* and its message block */
    ATLOCKINIT(sp->lock);
    ATLOCKINIT(sp->lockClose);
    ATLOCKINIT(sp->lockRemove);
    return 1;
}

adspRelease(gref)
    register gref_t *gref;	/* READ queue */
{
    register CCBPtr sp;
    int s, l;

    ATDISABLE(l, adspgen_lock);
    if (gref->info) {
	sp = (CCBPtr)gbuf_rptr(((gbuf_t *)gref->info));
	ATDISABLE(s, sp->lock);
	ATENABLE(s, adspgen_lock);
				/* Tells completion routine of close */
				/* packet to remove us. */

	if (sp->state == sPassive || sp->state == sClosed || 
	    sp->state == sOpening || sp->state == sListening) {
	    ATENABLE(l, sp->lock);
	    if (sp->state == sListening)
		CompleteQueue(&sp->opb, errAborted);
	    sp->removing = 1;	/* Prevent allowing another dspClose. */
	    DoClose(sp, errAborted, 0); /* will remove CCB */
	    return 0;
	} else {			/* sClosing & sOpen */
	    sp->state = sClosing;
	}
	ATENABLE(l, sp->lock);

	if (CheckOkToClose(sp)) { /* going to close */
	    sp->sendCtl = B_CTL_CLOSE; /* Send close advice */
	} else {
		CheckSend(sp);	/* try one more time to send out data */
		if (sp->state != sClosed)
		    sp->sendCtl = B_CTL_CLOSE; /* Setup to send close advice */
	}
	CheckSend(sp);		/* and force out the close */
	ATDISABLE(s, sp->lock);
	    sp->removing = 1;	/* Prevent allowing another dspClose. */
	    sp->state = sClosed;
	ATENABLE(s, sp->lock);
	    DoClose(sp, errAborted, 0);  /* to closed and remove CCB */
    } else
	ATENABLE(l, adspgen_lock);
}




adspWriteHandler(gref, mp)
    gref_t *gref;			/* WRITE queue */
    gbuf_t *mp;
{

    register ioc_t *iocbp;
    register struct adspcmd *ap;
    int error, flag;
	void *sp;

    switch(gbuf_type(mp)) {
    case MSG_DATA:
	if (gref->info == 0) {
	    gbuf_freem(mp);
	    return(STR_IGNORE);
        }
	/*
	 * Fill in the global stuff
	 */
	ap = (struct adspcmd *)gbuf_rptr(mp);
	ap->gref = gref;
	ap->ioc = 0;
	ap->mp = mp;
	sp = (void *)gbuf_rptr(((gbuf_t *)gref->info));
	switch(ap->csCode) {
	case dspWrite:
	    if ((error = adspWrite(sp, ap)))
		gbuf_freem(mp);
	    return(STR_IGNORE);
	case dspAttention:
	    if ((error = adspAttention(sp, ap)))
		gbuf_freem(mp);
	    return(STR_IGNORE);
	}
    case MSG_IOCTL:
	if (gref->info == 0) {
	    adspioc_ack(EPROTO, mp, gref);
	    return(STR_IGNORE);
        }
	iocbp = (ioc_t *) gbuf_rptr(mp);
	if (ADSP_IOCTL(iocbp->ioc_cmd)) {
	    iocbp->ioc_count = sizeof(*ap) - 1;
	    if (gbuf_cont(mp) == 0) {
		adspioc_ack(EINVAL, mp, gref);
		return(STR_IGNORE);
	    }
	    ap = (struct adspcmd *) gbuf_rptr(gbuf_cont(mp));
	    ap->gref = gref;
	    ap->ioc = (caddr_t) mp;
	    ap->mp = gbuf_cont(mp); /* request head */
	    ap->ioResult = 0;

	    if ((gref->info == 0) && ((iocbp->ioc_cmd != ADSPOPEN) &&
			            (iocbp->ioc_cmd != ADSPCLLISTEN))) {
	        ap->ioResult = errState;

		adspioc_ack(EINVAL, mp, gref);
		return(STR_IGNORE);
	    }
	}	
	sp = (void *)gbuf_rptr(((gbuf_t *)gref->info));
	switch(iocbp->ioc_cmd) {
	case ADSPOPEN:
	case ADSPCLLISTEN:
		ap->socket = ((CCBPtr)sp)->localSocket;
		flag = (adspMode(ap) == ocAccept) ? 1 : 0;
		if (flag && ap->socket) {
			if (adspDeassignSocket((CCBPtr)sp) >= 0)
				ap->socket = 0;
		}
		if ((ap->socket == 0) &&
		    ((ap->socket = 
		      (at_socket)adspAssignSocket(gref, flag)) == 0)) {
		    adspioc_ack(EADDRNOTAVAIL, mp, gref);
	        return(STR_IGNORE);
		}
	    ap->csCode = iocbp->ioc_cmd == ADSPOPEN ? dspInit : dspCLInit;
	    if ((error = adspInit(sp, ap)) == 0) {
		switch(ap->csCode) {
		case dspInit:
		    /* and open the connection */
		    ap->csCode = dspOpen;
		    error = adspOpen(sp, ap);
		    break;
		case dspCLInit:
		    /* ADSPCLLISTEN */
		    ap->csCode = dspCLListen;
		    error = adspCLListen(sp, ap);
		    break;
		}
	    }
	    if (error) 
		adspioc_ack(error, mp, gref); /* if this failed req complete */
	    return(STR_IGNORE);
	case ADSPCLOSE:
	    ap->csCode = dspClose;
	    if ((error = adspClose(sp, ap))) {
		adspioc_ack(error, mp, gref);
		break;
	    }
	    break;
	case ADSPCLREMOVE:
	    ap->csCode = dspCLRemove;
	    error = adspClose(sp, ap);
	    adspioc_ack(error, mp, gref);
	    return(STR_IGNORE);
	case ADSPCLDENY:
	    ap->csCode = dspCLDeny;
	    if ((error = adspCLDeny(sp, ap))) {
		adspioc_ack(error, mp, gref);
	    }
	    return(STR_IGNORE);
	case ADSPSTATUS:
	    ap->csCode = dspStatus;
	    if ((error = adspStatus(sp, ap))) {
		adspioc_ack(error, mp, gref);
	    }
	    return(STR_IGNORE);
	case ADSPREAD:
	    ap->csCode = dspRead;
	    if ((error = adspRead(sp, ap))) {
		adspioc_ack(error, mp, gref);
	    }
	    return(STR_IGNORE);
	case ADSPATTENTION:
	    ap->csCode = dspAttention;
	    if ((error = adspReadAttention(sp, ap))) {
		adspioc_ack(error, mp, gref);
	    }
	    return(STR_IGNORE);
	case ADSPOPTIONS:
	    ap->csCode = dspOptions;
	    if ((error = adspOptions(sp, ap))) {
		adspioc_ack(error, mp, gref);
	    }
	    return(STR_IGNORE);
	case ADSPRESET:
	    ap->csCode = dspReset;
	    if ((error = adspReset(sp, ap))) {
		adspioc_ack(error, mp, gref);
	    }
	    return(STR_IGNORE);
	case ADSPNEWCID:
	    ap->csCode = dspNewCID;
	    if ((error = adspNewCID(sp, ap))) {
		adspioc_ack(error, mp, gref);
	    }
	    return(STR_IGNORE);
	default:
	    return(STR_PUTNEXT);	/* pass it on down */
	}
	return(STR_IGNORE);
    case MSG_PROTO:
    default:
	gbuf_freem(mp);
    }
}


adspReadHandler(gref, mp)
    gref_t *gref;
    gbuf_t *mp;
{
    int error;

    switch(gbuf_type(mp)) {
    case MSG_DATA:
	if ((error = adspPacket(gref, mp))) {
	    gbuf_freem(mp);
	}
	break;
	
    case MSG_IOCTL:
    default:
	return(STR_PUTNEXT);
	break;
    }
    return(STR_IGNORE);
}

/*
 * adsp_sendddp()
 *
 * Description:
 *      This procedure a formats a DDP datagram header and calls the
 *      DDP module to queue it for routing and transmission according to
 *      the DDP parameters.  We always take control of the datagram;
 *      if there is an error we free it, otherwise we pass it to the next
 *      layer.  We don't need to set the src address fileds because the
 *      DDP layer fills these in for us.
 *
 * Calling Sequence:
 *      ret_status = adsp_sendddp(q, sp, mp, length, dstnetaddr, ddptype);
 *
 * Formal Parameters:
 *	sp		Caller stream pointer
 *      mp              gbuf_t chain containing the datagram to transmit
 *			The first mblk contains the ADSP header and space
 *			for the DDP header.
 *      length          size of data portion of datagram
 *      dstnetaddr      address of 4-byte destination internet address
 *      ddptype         DDP protocol to assign to the datagram
 *
 * Completion Status:
 *      0               Procedure successful completed.
 *      EMSGSIZE        Specified datagram length is too big.
 *
 * Side Effects:
 *      NONE
 */

adsp_sendddp(sp, mp, length, dstnetaddr, ddptype)
   CCBPtr sp;
   gbuf_t *mp;
   int length;
   AddrUnion *dstnetaddr;
   int ddptype;
{
   DDPX_FRAME   *ddp;
   gbuf_t *mlist = mp;

   if (mp == 0)
       return EINVAL;

   if (length > DDP_DATA_SIZE) {
       gbuf_freel(mlist);
       return EMSGSIZE;
   }

  while (mp) {

   if (length == 0)
       length = gbuf_msgsize(mp) - DDPL_FRAME_LEN;
   /* Set up the DDP header */

   ddp = (DDPX_FRAME *) gbuf_rptr(mp);
   UAS_ASSIGN(ddp->ddpx_length, (length + DDPL_FRAME_LEN));
   UAS_ASSIGN(ddp->ddpx_cksm, 0);
   if (sp) {
	if (sp->useCheckSum)
	   UAS_ASSIGN(ddp->ddpx_cksm, 1);
   }

   NET_ASSIGN(ddp->ddpx_dnet, dstnetaddr->a.net);
   ddp->ddpx_dnode = dstnetaddr->a.node;
   ddp->ddpx_source = sp ? sp->localSocket : ddp->ddpx_dest;
   ddp->ddpx_dest = dstnetaddr->a.socket;

   ddp->ddpx_type = ddptype;
   length = 0;
   mp = gbuf_next(mp);

  }
	   
   DDP_OUTPUT(mlist);
   return 0;
}

void NotifyUser(sp)
    register CCBPtr sp;

{
/*
    pidsig(sp->pid, SIGIO);
*/
}

void UrgentUser(sp)
    register CCBPtr sp;
{
/*
    pidsig(sp->pid, SIGURG);
*/
}
