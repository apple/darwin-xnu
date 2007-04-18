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
 * Packet.c 
 *
 * v01.23  All incoming packets come here first    06/21/90 mbs
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
#include <sys/ioctl.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/time.h>

#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/ddp.h>
#include <netat/at_var.h>

#include <netat/adsp.h>
#include <netat/adsp_internal.h>

extern at_ifaddr_t *ifID_home;

/*
 * GleanSession
 *
 * We just got a packet for this session, glean its address &
 * reset probe timer
 *
 * INPUTS:
 *    Session
 * OUTPUTS:
 *    none
 */
static void GleanSession(sp)		/* (CCBPtr sp) */
    CCBPtr sp;
{
    if (sp->openState == O_STATE_OPEN) {
	/* This is true for both state = sOpen & sClosing */
        RemoveTimerElem(&adspGlobal.slowTimers, &sp->ProbeTimer);
	InsertTimerElem(&adspGlobal.slowTimers, &sp->ProbeTimer, 
			sp->probeInterval);
	sp->probeCntr	= 4;
    }

}


/*
 * The same code handles incoming Open Connection Request,
 * Open Request + Ack, Open Connection Ack, Open Connection Denial
 *
 * We could be in four different states, LISTEN, OPENWAIT, ESTABLISHED,
 * OPEN.
 */

/*
 *
 * Ok, there are 16 combinations.  8 are do-nothings, 2 have to be
 * special cased (Open Deny and Req+Ack on Open session)
 *
 * Build a table of actions:
 *    Ignore?
 *    What to match on (local socket, whole address, DestCID, SrcCID)
 *    What to send (Ack or Req+Ack)
 *    Next State (both the ccb state and the open state)
 */

/*
 *
 */
typedef struct {
    u_char match;		/* Characteristics that have to match 
				 * (Bit-Mapped, see below) */
    char action;		/* What to do if CCB matches */
    char send;			/* What to send in response 
				 * (Bit mapped, same as sendCtl field of 
				 * CCB) */
    char openState;		/* Next Open state */
    char state;			/* Next ccb state. */
    char pad;			/* Too bad we need this to make structure 
				 * even size */
} TBL, *TBLPtr;

#define M_LSOC		0x01	/* bit  0 - Match on local socket */
#define M_ADDR		0x02	/* bit  1 - Match on whole address */
#define M_DCID		0x04	/* bit  2 - Match on DestCID */
#define M_SCID		0x08	/* bit  3 - Match SrcCID */
#define M_DCIDZERO	0x10	/* bit  4 - Dest CID must be 0 */
#define M_SCIDZERO	0x20	/* bit  5 - Src CID must be 0 */
#define M_FILTER	0x40	/* bit  6 - Match address filter */
#define M_IGNORE	0x80	/* bit  7 - Ignore */

#define A_COMPLETE	0x01	/* Complete open parameter block */
#define A_SAVEPARMS	0x02	/* Save connection parameters */
#define A_OREQACKOPEN	0x04	/* special case for open Req+Ack on 
				 * OPEN session */
#define A_GLEAN		0x08	/* We'll be talking back to this guy */
#define A_DENY		0x10	/* We've been denied! */


/*
 * So here's our table
 */

static TBL tbl[16] = {

/*
 * For Open Request ($81)
 *
 *	LISTENING
 *		Match on destination socket
 *		Match on address filter
 *		Dest CID must be 0
 *		Glean connection
 *		Save Open Connection parameters
 *		Send OREQACK
 *		Change state to ESTABLISHED
 */
	{	M_LSOC + M_DCIDZERO + M_FILTER,
	 	A_SAVEPARMS + A_GLEAN,
		B_CTL_OREQACK,
		O_STATE_ESTABLISHED,
		sOpening,
		0
	},

/*
 *
 *	OPENWAIT
 *		Match on Remote Address & destination socket
 *		Dest CID must be 0
 *		Save Open Connection parameters
 *		Send Ack
 *		Change state to ESTABLISHED
 */
	{	M_LSOC + M_ADDR + M_DCIDZERO,
	  	A_SAVEPARMS + A_GLEAN,
	  	B_CTL_OACK,
	  	O_STATE_ESTABLISHED,
		sOpening,
		0
	},
/*
 *
 *	ESTABLISHED
 *		Match on Remote Address & SrcCID
 *		Dest CID must be 0
 *		Send Req + Ack
 */
	{	M_ADDR + M_SCID + M_DCIDZERO, 
		A_GLEAN, 
		B_CTL_OACK, 
		O_STATE_ESTABLISHED,
		sOpening,
		0
	},
/*
 *	OPEN
 *		Ignore
 */
	{	M_IGNORE, 
		0, 
		0, 
		0,
		0,
		0
	},

/*
 *
 * For Open Ack ($82)
 *
 *	LISTENING
 *		Ignore
 */
	{	M_IGNORE, 
		0, 
		0, 
		0,
		0,
		0
	},
/*
 *
 *	OPENWAIT
 *		Ignore
 */
	{	M_IGNORE, 
		0, 
		0, 
		0, 
		0, 
		0
	},
/*
 *
 *	ESTABLISHED
 *		Match on SrcCID & DestCID & Address & Local Socket
 *		Complete Listen or Connect PB
 *		OPEN
 */
	{	M_ADDR + M_DCID + M_SCID + M_LSOC, 
		A_COMPLETE + A_GLEAN, 
		0, 
		O_STATE_OPEN,
		sOpen,
		0
	},
/*
 *
 *	OPEN
 *		Ignore
*/
	{	M_IGNORE, 
		0, 
		0, 
		0, 
		0, 
		0
	},

/*
 *
 * For Open Request + Ack ($83)
 *
 *	LISTENING
 *		Ignore
*/
	{	M_IGNORE, 
		0, 
		0, 
		0, 
		0, 
		0
	},
/*
 *
 *	OPENWAIT
 *		Match on DestCID & socket
 *			Do not test remote address -- our open req could have
 *			been passed to another address by a connection server
 *		Save Open Connection parameters
 *		Complete Connect parameter block
 *		Send Ack
 *		OPEN
 */
	{	M_DCID + M_LSOC,
		A_COMPLETE + A_SAVEPARMS + A_GLEAN,
	  	B_CTL_OACK,
	  	O_STATE_OPEN,
		sOpen,
		0
	},
/*
 *
 *	ESTABLISHED
 *		Ignore
 */
	{	M_IGNORE, 
		0, 
		0, 
		0, 
		0, 
		0
	},
/*
 *
 *	OPEN
 *		Match on Remote Address & SrcCID & DestCID & Local Socket
 *		If we've never gotten any data
 *		Send Ack & Retransmit
 */
	{	M_ADDR + M_DCID + M_SCID + M_LSOC,
	  	A_OREQACKOPEN + A_GLEAN,
	  	B_CTL_OACK,
	  	O_STATE_OPEN,
		sOpen,
		0
	},

/*
 *
 *
 * For Open Deny ($84)
 *
 *	LISTENING
 *		Ignore
 */
	{	M_IGNORE, 
		0, 
		0, 
		0, 
		0, 
		0
	},
/*
 *
 *	OPENWAIT
 *		Match on DestCID & Address
 *		Source CID must be 0
 *		Complete with error
 */
	{	M_SCIDZERO + M_DCID + M_ADDR, 
		A_DENY,
		0, 
		O_STATE_NOTHING,
		sClosed,
		0
	},
/*
 *
 *	ESTABLISHED
 *		Ignore
 */
	{	M_IGNORE, 
		0, 
		0, 
		0, 
		0, 
		0
	},	/* %%% No we probably don't want to ignore in this case */
/*
 *
 *    OPEN
 *       Ignore
 */
	{	M_IGNORE, 
		0, 
		0, 
		0, 
		0, 
		0
	}
};

extern at_ifaddr_t *ifID_table[];

/*
 * Used to search down queue of sessions for a session waiting for an
 * open request.
 */
typedef struct {
   AddrUnion	addr;
   word		dstCID;
   word		srcCID;
   byte		socket;
   byte		descriptor;
   byte		idx;		/* Index into state tables */
   TBLPtr	t;		/* Ptr to entry in table above */
} MATCH, *MATCHPtr;

/*
 * MatchStream
 *
 * Called by Rx connection to find which stream (if any) should get this open
 * request/ack/req+ack/deny packet.
 *
 */

static boolean
MatchStream(sp, m)		/* (CCBPtr sp, MATCHPtr m) */
    CCBPtr sp;
    MATCHPtr m;
{
	unsigned char match;
	struct adspcmd 	*opb;
    
	if (sp->openState < O_STATE_LISTEN ||
	    sp->openState > O_STATE_OPEN)
	    return 0;


	m->t = &tbl[sp->openState - O_STATE_LISTEN + m->idx];

	match = m->t->match;	/* Get match criteria */

	if (match & M_IGNORE)	/* Ignore this combination */
	    return 0;

	if (match & M_LSOC) {	/* Match on Local socket */
	    if (sp->localSocket != m->socket)
		return 0;
	}

	if (match & M_ADDR) {	/* Match on Address */
	    AddrUnion	addr;
	    addr = m->addr;	/* Make local copy for efficiency */
	    if (sp->remoteAddress.a.node != addr.a.node)
		return 0;
	    if (sp->remoteAddress.a.socket != addr.a.socket)
		return 0;
	    if (sp->remoteAddress.a.net && addr.a.net &&
		(sp->remoteAddress.a.net != addr.a.net))
		return 0;
			
	    /*
	     * Handle special case to reject self-sent open request
	     */
 	    if ((m->srcCID == sp->locCID) && 
		(addr.a.node == ifID_home->ifThisNode.s_node) &&
		/* *** was (addr.a.node == ddpcfg.node_addr.node) && *** */
 		((addr.a.net == 0) || 
 		 (ifID_home->ifThisNode.s_net == 0) || 
 		 (ifID_home->ifThisNode.s_net == addr.a.net)) )
	      /* *** was 
		(NET_VALUE(ddpcfg.node_addr.net) == 0) || 
 		(NET_VALUE(ddpcfg.node_addr.net) == NET_VALUE(addr.a.net))) )
		 *** */
				/* CID's match, and */
				/* If nodeID matches, and */
				/* network matches, */
		return 0;	/* then came from us! */
	}
	
	if (match & M_DCID) {	/* Match on DestCID */
	    if (sp->locCID != m->dstCID)
		return 0;
	}
	
	if (match & M_SCID) {	/* Match on SourceCID */
	    if (sp->remCID != m->srcCID)
		return 0;
	}
	
	if (match & M_DCIDZERO)	{ /* Destination CID must be 0 */
	    if (m->dstCID != 0)
		return 0;
	}
	
	if (match & M_SCIDZERO)	/* Source CID must be 0 */
	{
	    if (m->srcCID != 0)
		return 0;
	}
	
	if (match & M_FILTER) {	/* Check address filter? */
	    if ((opb = sp->opb)) /* There should be a param block... */
	    {
		AddrUnion	addr;
		addr = m->addr;	/* Make local copy for efficiency */
		if ((opb->u.openParams.filterAddress.net && 
		     addr.a.net &&
		     opb->u.openParams.filterAddress.net != addr.a.net) ||
		    (opb->u.openParams.filterAddress.node != 0 &&
		     opb->u.openParams.filterAddress.node != addr.a.node)||
		    (opb->u.openParams.filterAddress.socket != 0 &&
		     opb->u.openParams.filterAddress.socket != addr.a.socket))
		    return 0;
	    }
	}
	
	return 1;
}

/*
 * MatchListener
 *
 * Called by rx connection to see which connection listener (if any) should
 * get this incoming open connection request.
 *
 */

static boolean MatchListener(sp, m) /* (CCBPtr sp, MATCHPtr m) */
    CCBPtr sp;
    MATCHPtr m;
{

    if ((sp->state == (word)sListening) && /* This CCB is a listener */
	(sp->localSocket == m->socket))	/* on the right socket */
	return 1;
    
    return 0;
}

/*
 * RXConnection
 *
 * We just received one of the 4 Open Connection packets
 * Interrupts are masked OFF at this point
 *
 * INPUTS:
 *	spPtr	Place to put ptr to stream (if we found one -- not 
 *						for listeners)
 *	f	Pointer to ADSP header for packet, data follows behind it
 *	len	# of byte in ADSP header + data
 *	addr	Who sent the packet
 *	dsoc	Where they sent it to
 *
 * OUTPUTS:
 *    Returns 1 if packet was ignored
 */
static int RXConnection(gref, spPtr, f, len, addr, dsoc) 
    /* (CCBPtr *spPtr, ADSP_FRAMEPtr f, word len, AddrUnion addr, byte dsoc) */
    gref_t *gref;			/* READ queue */
    CCBPtr *spPtr;
    ADSP_FRAMEPtr f;
    int len;
    AddrUnion addr;
    unsigned char dsoc;
{
    CCBPtr sp;
    ADSP_OPEN_DATAPtr op;
    struct adspcmd *pb;
    MATCH m;
    gbuf_t *mp;
    ADSP_FRAMEPtr adspp;
    ADSP_OPEN_DATAPtr adspop;

    op = (ADSP_OPEN_DATAPtr)&f->data[0]; /* Point to Open-Connection parms */
    len -= ADSP_FRAME_LEN;
    
    if (len < (sizeof(ADSP_OPEN_DATA))) /* Packet too small */
	return 1;


    if (UAS_VALUE(op->version) != netw(0x0100)) { /* Check version num (on even-byte) */
	/*
	 * The open request has been denied.  Try to send him a denial.  
	 */

	mp = gbuf_alloc(AT_WR_OFFSET + DDPL_FRAME_LEN + ADSP_FRAME_LEN + ADSP_OPEN_FRAME_LEN,
		    PRI_LO);
	gbuf_rinc(mp,AT_WR_OFFSET);
	gbuf_wset(mp,DDPL_FRAME_LEN);
	adspp = (ADSP_FRAMEPtr)gbuf_wptr(mp);
	gbuf_winc(mp,ADSP_FRAME_LEN);
	bzero((caddr_t) gbuf_rptr(mp),DDPL_FRAME_LEN + ADSP_FRAME_LEN + 
	      ADSP_OPEN_FRAME_LEN);
	adspp->descriptor = ADSP_CONTROL_BIT | ADSP_CTL_ODENY;
	adspop = (ADSP_OPEN_DATAPtr)gbuf_wptr(mp);
	gbuf_winc(mp,ADSP_OPEN_FRAME_LEN);
	UAS_UAS(adspop->dstCID, f->CID);
	UAS_ASSIGN_HTON(adspop->version, 0x100);
	adsp_sendddp(0, mp, DDPL_FRAME_LEN + ADSP_FRAME_LEN + 
		   ADSP_OPEN_FRAME_LEN, &addr, DDP_ADSP);

	return 0;
    }
    m.addr = addr;
    m.socket = dsoc;
    m.descriptor = f->descriptor;
    m.srcCID = UAS_VALUE_NTOH(f->CID);
    m.dstCID = UAS_VALUE_NTOH(op->dstCID);	/* On even-byte boundry */
    m.idx = ((f->descriptor & ADSP_CONTROL_MASK) - 1) * 4;
                                          
    /*
     * See if we can find a stream that knows what to do with this packet
     */
    if ((sp = (CCBPtr)qfind_m(AT_ADSP_STREAMS, &m, (ProcPtr)MatchStream)) == 0)
    {
	struct adspcmd *p;
	struct adspcmd *n;
	/*
	 * No match, so look for connection listeners if this is an 
	 * open request
	 */
	if ((f->descriptor & ADSP_CONTROL_MASK) != (byte)ADSP_CTL_OREQ)
	    return 1;

	if ((sp = (CCBPtr)qfind_m(AT_ADSP_STREAMS, &m, 
				  (ProcPtr)MatchListener)) == 0)
	    return 1;

	p = (struct adspcmd *)&sp->opb;
	while (n = (struct adspcmd *)p->qLink) /* Hunt down list of listens */
	{
	    /* Check address filter */
	    if (((n->u.openParams.filterAddress.net == 0) ||
		 (addr.a.net == 0) ||
		 (n->u.openParams.filterAddress.net == addr.a.net)) &&
		
		((n->u.openParams.filterAddress.node == 0) || 
		 (n->u.openParams.filterAddress.node == addr.a.node)) &&
		
		((n->u.openParams.filterAddress.socket == 0) || 
		 (n->u.openParams.filterAddress.socket == addr.a.socket))) {
		p->qLink = n->qLink; /* Unlink this param block */
		n->u.openParams.remoteCID = m.srcCID;
		*((AddrUnionPtr)&n->u.openParams.remoteAddress)	= addr;
		n->u.openParams.sendSeq	= UAL_VALUE_NTOH(f->pktNextRecvSeq);
		n->u.openParams.sendWindow = UAS_VALUE_NTOH(f->pktRecvWdw);
		n->u.openParams.attnSendSeq = UAL_VALUE_NTOH(op->pktAttnRecvSeq);
		n->ioResult = 0;
		completepb(sp, n); /* complete copy of request */
				/* complete(n, 0); */
		return 0;
	    }			/* found CLListen */
			
	    p = n;		/* down the list we go... */
			
	}			/* while */
		
	return 1;
    }
	
    *spPtr = sp;		/* Save ptr to stream we just found */
	
    sp->openState = m.t->openState; /* Move to next state (may be same) */
    sp->state = m.t->state;	/* Move to next state (may be same) */

    if (m.t->action & A_SAVEPARMS) { /* Need to Save open-conn parms */
	sp->firstRtmtSeq = sp->sendSeq = UAL_VALUE_NTOH(f->pktNextRecvSeq);
	sp->sendWdwSeq = UAL_VALUE_NTOH(f->pktNextRecvSeq) + UAS_VALUE_NTOH(f->pktRecvWdw) - 1;
	sp->attnSendSeq = UAL_VALUE_NTOH(op->pktAttnRecvSeq); /* on even boundry */

		
	sp->remCID = UAS_VALUE_NTOH(f->CID);	/* Save Source CID as RemCID */
	UAS_UAS(sp->of.dstCID, f->CID);	/* Save CID in open ctl packet */
		
	sp->remoteAddress = addr; /* Save his address */

    }

    if (m.t->action & A_DENY) {	/* We've been denied ! */
	DoClose(sp, errOpenDenied, -1);
    }

    if (m.t->action & A_OREQACKOPEN) { 
				/* Special case for OREQACK */
				/* on an open session */
        RemoveTimerElem(&adspGlobal.fastTimers, &sp->RetryTimer);
	sp->sendSeq = sp->firstRtmtSeq;
	sp->pktSendCnt	= 0;
	sp->waitingAck	= 0;
	sp->callSend = 1;
    }

    if (m.t->send) {		/* Need to send a response */
	sp->sendCtl |= m.t->send;
	sp->callSend = 1;
    }

    if (m.t->action & A_COMPLETE) { /* Need to complete open param blk */
        RemoveTimerElem(&adspGlobal.slowTimers, &sp->ProbeTimer);
			
	if (pb = sp->opb) {
	    sp->opb = 0;
	    pb->u.openParams.localCID = sp->locCID;
	    pb->u.openParams.remoteCID = sp->remCID;
	    pb->u.openParams.remoteAddress = 
		*((at_inet_t *)&sp->remoteAddress);
	    pb->u.openParams.sendSeq = sp->sendSeq;
	    pb->u.openParams.sendWindow = sp->sendWdwSeq - sp->sendSeq;
	    pb->u.openParams.attnSendSeq = sp->attnSendSeq;
	    pb->ioResult = 0;
	    completepb(sp, pb);	/* complete(pb, 0); */
	    return 0;
	}
				/* Start probe timer */
	InsertTimerElem(&adspGlobal.slowTimers, &sp->ProbeTimer, 
			sp->probeInterval);
    }
    return 0;
}

/*
 * ADSPPacket
 *
 * When a packet is received by the protocol stack with DDP type equal
 * to ADSP, then execution comes here
 *
 * DS is set to ATALK's DGROUP
 *
 * This routine, or one of its children MUST call glean packet
 *
 * INPUTS:
 *    Pointer to DDP header 
 * OUTPUTS:
 *    none
 *
 * Note that the incoming message block (mp) is usually discarded, either
 * by the "ignored" path, or via the "checksend" path.  The only case
 * where the message is NOT freed is via the RxData case in the
 * non control packet switch.  I zero mp after the RxData case succeeds
 * so that mp will not be freed.
 */
int adspPacket(gref, mp) 
    /* (bytePtr data, word len, AddrUnion a, byte dsoc) */
    gref_t *gref;
    gbuf_t *mp;
{
    unsigned char *bp;
    int len;
    AddrUnion a;
    int dsoc;
    register DDPX_FRAME *ddp;	/* DDP frame pointer */
    register ADSP_FRAMEPtr f;	/* Frame */
    CCBPtr sp;

    sp = 0;			/* No stream */
    bp = (unsigned char *)gbuf_rptr(mp);
    ddp = (DDPX_FRAME *)bp;
    if (ddp->ddpx_type != DDP_ADSP)
	return -1;
    f = (ADSP_FRAMEPtr)(bp + DDPL_FRAME_LEN);

    len = UAS_VALUE_NTOH(ddp->ddpx_length) & 0x3ff; /* (ten bits of length) */
    len -= DDPL_FRAME_LEN;
    if (len < (sizeof(ADSP_FRAME) - 1))	/* Packet too small */
	return -1;		/* mark the failure */

    a.a.net = NET_VALUE(ddp->ddpx_snet);
    a.a.node = ddp->ddpx_snode;
    a.a.socket = ddp->ddpx_source;

    dsoc = ddp->ddpx_dest;

    if (sp = (CCBPtr)FindSender(f, a))
	GleanSession(sp);

    if (f->descriptor & ADSP_ATTENTION_BIT) { /* ATTN packet */
	if (sp && RXAttention(sp, mp, f, len)) 
	    goto ignore;
	else
	    mp = 0;		/* attention data is being held */
    }				/* ATTENTION BIT */

    else if (f->descriptor & ADSP_CONTROL_BIT) { /* Control packet */
	switch (f->descriptor & ADSP_CONTROL_MASK) {
	case ADSP_CTL_PROBE:	/* Probe or acknowledgement */
	    if (sp)
		CheckRecvSeq(sp, f);
	    break;

	case ADSP_CTL_OREQ:	/* Open Connection Request */
	case ADSP_CTL_OREQACK:	/* Open Request and acknowledgement */
	case ADSP_CTL_OACK:	/* Open Request acknowledgment */
	case ADSP_CTL_ODENY:	/* Open Request denial */
	    if (RXConnection(gref, &sp, f, len, a, dsoc))
		goto ignore;
	    break;
			
	case ADSP_CTL_CLOSE:	/* Close connection advice */
	    if (sp) {
		/* This pkt may also ack some data we sent */
		CheckRecvSeq(sp, f); 
		RxClose(sp);
		sp = 0;
	    } else
		goto ignore;
	    break;

	case ADSP_CTL_FRESET:	/* Forward Reset */
				/* May I rot in hell for the code below... */
	    if (sp && (CheckRecvSeq(sp, f), RXFReset(sp, f)))
		goto ignore;
	    break;
			
	case ADSP_CTL_FRESET_ACK: /* Forward Reset Acknowledgement */
	    if (sp && (CheckRecvSeq(sp, f), RXFResetAck(sp, f)))
		goto ignore;
	    break;

	case ADSP_CTL_RETRANSMIT: /* Retransmit advice */
	    if (sp) {
		/* This pkt may also ack some data we sent */
		CheckRecvSeq(sp, f); 
		RemoveTimerElem(&adspGlobal.fastTimers, &sp->RetryTimer);
		sp->sendSeq = sp->firstRtmtSeq;
		sp->pktSendCnt = 0;
		sp->waitingAck = 0;
		sp->callSend = 1;
	    } else
		goto ignore;
	    break;
			
	default:
	    goto ignore;
	}			/* switch */
    }				/* Control packet */

    else {			/* Data Packet */
	if ((sp == 0) || RXData(sp, mp, f, len))
	    goto ignore;
	else
	    mp = 0;		/* RXData used up the data, DONT free it! */
    }				/* Data Packet */

    if (mp)
	gbuf_freem(mp);

checksend:			/* incoming data was not ignored */
    if (sp && sp->callSend)	/* If we have a stream & we need to send */
	CheckSend(sp);
    
    return 0;
	
ignore:
    gbuf_freem(mp);
    return 0;
}
