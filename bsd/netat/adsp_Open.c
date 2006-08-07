/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* adspOpen.c v01.20
 *
 * From v01.20 08/23/90 Mike Shoemaker for MacOS
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
#include <sys/socketvar.h>
#include <sys/time.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>


/*
 * NextCID
 * 
 * Create a unique connection ID.
 *
 * INPUTS:
 * 		none
 * OUTPUTS:
 * 		unique connection ID
 */
unsigned short NextCID()
{
	unsigned short num;
	register CCB *queue;

	while (1) {
	    num = ++adspGlobal.lastCID;
	    /* qfind_w below is in 68K assembly */
	    /* point to the first element */
	    queue = (CCB *)AT_ADSP_STREAMS;
	    while (queue) {
		    /* and scan .. */
		    if (queue->locCID == num)
			break;
		    queue = queue->ccbLink;
	    }
	    if (queue == (CCBPtr)NULL)
		break;	
	}
	return num;
}

static	byte xlateStateTbl[4] =	/* The value to be given to the CCB's state. */
{				/* indexed by ocMode */
	sOpening,		/* ocRequest */
	sPassive,		/* ocPassive */
	sOpening,		/* ocAccept */
	sOpen			/* ocEstablish */
};
static	byte xlateOpenTbl[4] =	/* Value to use for open state. */
{				/* indexed by ocMode */
	O_STATE_OPENWAIT,	/* ocRequest */
	O_STATE_LISTEN,		/* ocPassive */
	O_STATE_ESTABLISHED,	/* ocAccept */
	O_STATE_OPEN		/* ocEstablish */
};

/*
 * adspOpen
 * 
 * INPUTS:
 * 	-->	ccbRefNum	refnum of connection end
 *	-->	remoteCID	connection id of remote connection end
 *	-->	remoteAddress	internet address of remote connection end
 *	-->	filterAddress	filter for incoming open connection requests
 *	-->	sendSeq		initial send sequence number to use
 *	-->	sendWindow	initial size of remote end's receive buffer
 *	--> 	recvSeq		initial receive sequence number to use
 *	--> 	attnSendSeq	initial attention send sequence number
 *	-->	attnRecvSeq	initial receive sequence number
 *	-->	ocMode		connection opening mode
 *	-->	ocMaximum	maximum retries of open connection request
 *
 * OUTPUTS:
 *	<--	localCID	connection identifier of this connection end
 *	<--	remoteCID	connection id of remote connection end
 *	<--	remoteAddress
 *	<--	sendSeq
 *	<-- 	sendWindow
 *	<--	attnSendSeq
 *
 * ERRORS:
 *		errRefNum	bad connection refnum
 *		errState	connection end must be closed
 *		errOpening	open connection attempt failed
 *		errAborted	request aborted by a remove or close call
 */
int adspOpen(sp, pb)		/* (DSPPBPtr pb) */
    register CCBPtr sp;
    register struct adspcmd *pb;
{
    extern int adsp_pidM[];

    int ocMode;
    register gbuf_t *mp;

    if (sp == 0) {
	pb->ioResult = errRefNum; /* Unknown refnum */
	return EINVAL;
    }
	
    if ((sp->state != sClosed) || 
	(sp->removing)) { /* The CCB must be closed */
	pb->ioResult = errState;
	return EALREADY;
    }

    ocMode = pb->u.openParams.ocMode; /* get a local copy of open mode */
	if (ocMode == ocRequest)
		adsp_pidM[pb->socket] = 0;
	
    /*
     * Save parameters.  Fill in defaults if zero
     */
    if (pb->u.openParams.ocInterval)
	sp->openInterval = pb->u.openParams.ocInterval;
    else
	sp->openInterval = ocIntervalDefault;
    
    if (pb->u.openParams.ocMaximum)
	sp->openRetrys = pb->u.openParams.ocMaximum;
    else
	sp->openRetrys = ocMaximumDefault;
    
    sp->remoteAddress = *((AddrUnionPtr)&pb->u.openParams.remoteAddress);
    /* Not used for passive */
    /*
     * Clear out send/receive buffers.
     */
    if (sp->sbuf_mb) { /* clear the send queue */
	gbuf_freel(sp->sbuf_mb);
	sp->sbuf_mb = 0;
    }
    if (sp->csbuf_mb) {
	gbuf_freem(sp->csbuf_mb);
	sp->csbuf_mb = 0;
    }
    if (sp->rbuf_mb) { /* clear the receive queue */
	gbuf_freel(sp->rbuf_mb);
	sp->rbuf_mb = 0;
    }
    if (sp->crbuf_mb) {
	gbuf_freem(sp->crbuf_mb);
	sp->crbuf_mb = 0;
    }

    sp->rData = 0;		/* Flag both buffers as empty */
    sp->sData = 0;
    sp->recvQPending = 0;	/* No bytes in receive queue */
    
    /*
     * Clear all of those pesky flags
     */
    sp->userFlags = 0;
    sp->sendDataAck = 0;
    sp->sendAttnAck = 0;
    sp->sendAttnData = 0;
    sp->callSend = 0;
    sp->removing = 0;
    sp->writeFlush = 0;
	
    /*
     * Reset round-trip timers
     */
    sp->roundTrip = sp->rtmtInterval;
    sp->deviation = 0;
    
    /*
     * Reset stuff for retransmit advice packet
     */
    sp->badSeqCnt = 0;
    /*
     * Reset flow control variables
     */
    sp->pktSendMax = 1;	/* Slow start says we should set this to 1 */
    sp->pktSendCnt = 0;
    sp->rbufFull = 0;
    sp->resentData = 0;
    sp->noXmitFlow = 0;
    sp->waitingAck = 0;
    
    /*
     * Copy required information out of parameter block
     */
    if (ocMode == ocAccept || ocMode == ocEstablish) {
	sp->remCID = pb->u.openParams.remoteCID;
	sp->sendSeq = sp->firstRtmtSeq = pb->u.openParams.sendSeq;
	sp->sendWdwSeq = sp->sendSeq + pb->u.openParams.sendWindow;
	sp->attnSendSeq = pb->u.openParams.attnSendSeq;
    } else {			/* accept or establish */
	sp->remCID = 0;
	sp->sendSeq = 0;
	sp->sendWdwSeq = 0;
	sp->attnSendSeq = 0;
    }
	
    if (ocMode == ocEstablish) { /* Only set these if establish mode */
	sp->recvSeq = pb->u.openParams.recvSeq;
	sp->attnRecvSeq = pb->u.openParams.attnRecvSeq;
	UAS_ASSIGN_HTON(sp->f.CID, sp->locCID); /* Preset the CID in the ADSP header */
	/* This is done elsewhere for all other modes */
	InsertTimerElem(&adspGlobal.slowTimers, &sp->ProbeTimer, 
			sp->probeInterval);
    } else {			/* establish */
	/* All other modes need a CID assigned */
	sp->locCID = NextCID();
	sp->recvSeq = 0;
	sp->attnRecvSeq = 0;
    }

    /*
     * Now set the state variables for this CCB.  
     */

    sp->openState = xlateOpenTbl[ocMode-ocRequest];
    sp->state = xlateStateTbl[ocMode-ocRequest];
	
    if (ocMode == ocEstablish) { /* For establish call, we're done */
	pb->ioResult = 0;
	adspioc_ack(0, pb->ioc, pb->gref);
	return 0;
    }
    
    pb->qLink = 0;		/* Clear link field before putting on queue */
    mp = gbuf_copym(pb->mp);	/* Save parameter block to match later */
    
    if (mp == 0) {
	    pb->ioResult = errDSPQueueSize;
	    return ENOBUFS;
    }
    pb->ioResult = 1;	/* not open -> not done */
    adspioc_ack(0, pb->ioc, pb->gref); /* release user */
    sp->opb = (struct adspcmd *)gbuf_rptr(mp);
    sp->opb->ioc = 0;		/* unlink saved pb from ioctl block */
    sp->opb->mp = mp;

    /*
     * For request & accept, need to send a packet
     */
    if ((ocMode == ocRequest) || (ocMode == ocAccept)) {
	sp->sendCtl |= (1 << (ocMode == ocRequest ? 
			      ADSP_CTL_OREQ : ADSP_CTL_OREQACK));
	CheckSend(sp);
    }
    return 0;
}

int adspMode(pb)
    register struct adspcmd *pb;
{
    return pb->u.openParams.ocMode;
}
