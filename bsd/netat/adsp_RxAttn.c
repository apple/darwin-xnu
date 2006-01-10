/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * RxAttn.c 
 *
 * From v01.12  06/12/90 mbs
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
 * Used to search down queue of sessions for a session that matches
 * sender and source connection ID
*/
typedef struct
{
	AddrUnion   addr;
	word        srcCID;
} MATCH_SENDER, *MATCH_SENDERPtr;

/*
 * MatchSender
 *
 */

static boolean MatchSender(sp, m) /* (CCBPtr sp, MATCH_SENDERPtr m) */
    CCBPtr sp;
    MATCH_SENDERPtr m;
{

    if (sp->state != sOpen && sp->state != sClosing)
	return 0;

    if (sp->remCID != m->srcCID)
	return 0;

    if (sp->remoteAddress.a.node != m->addr.a.node)
	return 0;
    if (sp->remoteAddress.a.socket != m->addr.a.socket)
	return 0;
    if (sp->remoteAddress.a.net && m->addr.a.net &&
	(sp->remoteAddress.a.net != m->addr.a.net))
	return 0;

    return 1;
}


/*
 * FindSender
 *
 * Given an ADSP Packet, find the stream it is associated with.
 *
 * This should only be used for ADSP Packets that could be received
 * by an OPEN connection.
 *
 * INPUTS:
 *    Pointer to ADSP header & address of sender
 * OUTPUTS:
 *    Pointer to stream if found, else 0
 */
CCBPtr FindSender(f, a)		/* (ADSP_FRAMEPtr f, AddrUnion a) */
    ADSP_FRAMEPtr f;
    AddrUnion a;
{
    MATCH_SENDER m;

    m.addr = a;
    m.srcCID = UAS_VALUE(f->CID);
    return (CCBPtr)qfind_m(AT_ADSP_STREAMS, &m, (ProcPtr)MatchSender);
}

/*
 * RXAttention
 *
 * We just got an Attention Packet.
 * See if it came from anybody we know.
 * Then check to see if it is an attention data packet or acknowledgement
 *
 * Interrupts are masked OFF at this point.
 *
 * INPUTS:
 *    stream pointer
 *    Pointer to ADSP header,
 *    Length of header plus data
 * OUTPUTS:
 *    Returns 1 if packet was ignored
 */
int RXAttention(sp, mp, f, len)	/* (CCBPtr sp, ADSP_FRAMEPtr f, word len) */
    CCBPtr sp;
    gbuf_t *mp;
    ADSP_FRAMEPtr f;
    int len;
{
    int offset;
    struct adspcmd *pb;
    long diff;

    if (UAS_VALUE(f->pktRecvWdw))		/* This field must be 0 in attn pkts */
	return 1;

    if ((f->descriptor == 
	 (char)(ADSP_ATTENTION_BIT | ADSP_ACK_REQ_BIT)) && /* Attention Data */
	((sp->userFlags & eAttention) == 0)) /* & he read the previous */
    {
	diff = netdw(UAL_VALUE(f->pktFirstByteSeq)) - sp->attnRecvSeq;
	if (diff > 0)		/* Hey, he missed one */
	    return 1;

	if (diff == 0)		/* This is the one we expected */
	{
	    len	-= ADSP_FRAME_LEN; /* remove adsp header */
	    if (len < 2)	/* Poorly formed attn packet */
		return 1;
	    sp->attnCode = (f->data[0] << 8) + f->data[1]; /* Save attn code */
	    sp->attn_mb = mp;
	    offset = ((unsigned char *)&f->data[2]) - (unsigned char *)gbuf_rptr(mp);
	    gbuf_rinc(mp,offset);
	    sp->attnPtr = (unsigned char *)gbuf_rptr(mp);
	    mp = 0;		/* mp has been queued don't free it */

	    /* Interrupts are off here, or otherwise we have to do 
	     * these three operations automically.
	     */
	    sp->attnSize = len - 2; /* Tell user how many bytes */
	    ++sp->attnRecvSeq;
	    /* Set flag saying we got attn message */
	    sp->userFlags |= eAttention;
	    UrgentUser(sp);	/* Notify user */
				/* BEFORE sending acknowledge */
	}			/* in sequence */

	sp->sendAttnAck = 1;	/* send attention ack for dupl. & 
				 * expected data */
	sp->callSend = 1;
    }				/* Attn Data */

    /*
     * Interrupts are OFF here, otherwise we have to do this atomically
     */
    /* Check to see if this acknowledges anything */
    if ((sp->attnSendSeq + 1) == netdw(UAL_VALUE(f->pktNextRecvSeq))) {
	sp->attnSendSeq++;
	if ((pb = sp->sapb) == 0) { /* We never sent data ? !!! */
	    if (mp)
		gbuf_freem(mp);
	    return 0;
	}
		
	sp->sapb = (struct adspcmd *)pb->qLink;	/* Unlink from queue */
		
	/* Remove timer */
	RemoveTimerElem(&adspGlobal.fastTimers, &sp->AttnTimer); 
	
	pb->ioResult = 0;
	if (gbuf_cont(pb->mp)) {
	    gbuf_freem(gbuf_cont(pb->mp)); /* free the data */
	    gbuf_cont(pb->mp) = 0;
	}
	completepb(sp, pb);	/* Done with the send attention */
		
	if (sp->sapb) {		/* Another send attention pending? */
	    sp->sendAttnData = 1;
	    sp->callSend = 1;
	} else {
	    if (sp->state == sClosing) /* this ack may allow us to close... */
		CheckOkToClose(sp);
	}
    }
    if (mp)
	gbuf_freem(mp);
    return 0;
}
