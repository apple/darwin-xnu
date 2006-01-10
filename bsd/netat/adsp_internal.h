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
#ifndef _NETAT_ADSP_INTERNAL_H_
#define _NETAT_ADSP_INTERNAL_H_

#include <sys/types.h>

#ifdef __APPLE_API_OBSOLETE
#ifdef KERNEL_PRIVATE

/* from h/adsp_portab.h */

/* TypeDefs for the basic data bytes. */

typedef unsigned char		byte, *bytePtr;

#ifdef NOT_USED
typedef char			int8;
typedef short 			int16;
typedef int 			int32;
#endif

typedef unsigned char		boolean;

typedef unsigned short		word;

typedef unsigned int 		dword;

#define BYTE_AT(x)		(*((byte PTR)(x)))
#define WORD_AT(x)		(*((word PTR)(x)))
#define DWORD_AT(x)		(*((dword PTR)(x)))

#define high(x)			((byte)((x) >> 8))
#define low(x)			((byte)(x))
#define hlword(h, l)		(((byte)(l)) | (((byte)(h)) << 8))


/* 
 * On a Mac, there is no need to byte-swap data on the network, so 
 * these macros do nothing 
 */

#define netw(x)		x
#define netdw(x)	x

typedef struct
{
  at_net           network;       /* network number */
  byte           nodeid;        /* node number    */
  byte           socket;        /* socket number  */
} AddrBlk, *AddrBlkPtr;

typedef union
{
   at_inet_t     a;
} AddrUnion, *AddrUnionPtr;

/* End Portab.h */

/* from h/adsp_internal.h */

#undef T_IDLE

/*
* Default Behavior for ADSP
*/
#define	ocIntervalDefault	6
#define ocMaximumDefault	10
#define probeIntervalDefault	180

/*
* MACROS for comparing 32-bit sequence numbers
*/
#define GT(x,y)  (((long)(x-y)) > (long) 0)
#define LT(x,y)  (((long)(x-y)) < (long) 0)
#define GTE(x,y) (((long)(x-y)) >= (long) 0)
#define LTE(x,y) (((long)(x-y)) <= (long) 0)
#define BETWEEN(x,y,z) (LTE(x,y) && LTE(y,z))

/*
 * Use the kernel tick counter for SysTicks.
 */

#define SysTicks()	lbolt

/*
 * Timer element used for handling timings
 */
typedef struct timerelem {
    struct timerelem *link;
    short timer;
    char type;
    unsigned onQ:1;		/* Bit-fields are faster than booleans */
} TimerElem;

typedef TimerElem *TimerElemPtr;

/*
 * For AppleTalk Phase 2 event queue
 */
typedef struct {
    Ptr	qLink;
    unsigned short qType;
    ProcPtr callAddr;
} LAPEventElem;

typedef LAPEventElem *LAPEventElemPtr;

/* 
 * The Event types we're passed when an AppleTalk transition occurs
 */
#define AOpenTransition		0
#define	ACloseTransition	2
#define ANetworkTransition	5

/*
 * The element we're passed when a NetworkTransaction event occurs
 */
typedef struct TNetworkTransition {
    Ptr	private;		/* pointer used internally by NetShare */
    ProcPtr netValidProc;	/* pointer to the network valid procedure */
} TNetworkTransition, *TPNetworkTransition;

typedef long (*NetworkTransitionProcPtr)(TPNetworkTransition nettrans, 
				   unsigned long thenet);
/*
 * This is the connection control block
 */
typedef struct ccb {
    /*---These fields may not change order or size-----------*/

    struct ccb *ccbLink;	/* link to next ccb */
    unsigned short state;	/* state of the connection end */
    unsigned char userFlags;	/* flags for unsolicited connection events */
    unsigned char localSocket;	/* socket number of this connection end */
    AddrUnion remoteAddress;	/* internet address of remote end */
    unsigned short attnCode;	/* attention code received */
    unsigned short attnSize;	/* size of received attention data */
    unsigned char *attnPtr;	/* ptr to received attention data */
    unsigned short recvQPending; /* # bytes in receive queue %%% */
    /*------------------------------------------------------ */
	
    struct adspcmd *opb;	/* Outstanding open/close/remove/listens */
    struct adspcmd *spb;	/* Outstanding Sends */
    struct adspcmd *sapb;	/* Outstanding Send Attentions */
    struct adspcmd *frpb;	/* Outstanding Forward Resets */
    struct adspcmd *rpb;	/* Outstanding Read Requests */
	
    struct ccb *otccbLink;	/* link to next ccb */
    int pid;		/* Process ID for CCB owner */

    unsigned short remCID;	/* Remote Connection ID */
    unsigned short locCID;	/* Local Connection ID */
    int sendSeq;		/* Seq number of next char to send to remote */
    int firstRtmtSeq;		/* oldest seq # in local send queue */
    int sendWdwSeq;		/* Seq # of last char remote has bfr for */
    int recvSeq;		/* Seq of # of next char expected from rmte */
    int recvWdw;		/* # of bytes local end has buffer space for */
    int attnSendSeq;		/* Seq # of next attn pkt to send to remote */
    int attnRecvSeq;		/* Seq # of next packet local end expects */
    int maxSendSeq;		/* Highest seq # we ever sent on connection */

    /* These must be in the first 255 bytes of the CCB */
    TimerElem ProbeTimer;	/* Timer element for probes (and open) */
    TimerElem FlushTimer;	/* Timer element for flushing data */
    TimerElem RetryTimer;	/* Timer element for retransmissions */
    TimerElem AttnTimer;	/* Timer element for attention packets */
    TimerElem ResetTimer;	/* Timer element for forward resets */
	
    short openInterval;		/* Interval between open connection packets */
    short probeInterval;	/* Interval between probes */
    short sendInterval;		/* Interval before automatic flush */
    short rtmtInterval;		/* Rexmit interval (dynamically determined) */

    short sendCtl;		/* Send control message bits */
    short sendBlocking;		/* Flush unsent data if > than sendBlocking */
    short openRetrys;		/* # of retrys for Connect & Accept */
    short rbuflen;		/* Total size of receive buffer */
    short sbuflen;		/* Total size of receive buffer */
    char pad;
    char lockFlag;
    char badSeqMax;		/* retransmit advice send threshold */
    char badSeqCnt;		/* # of of out-of-order packets received */
    char useCheckSum;		/* true to use DDP checksums */
    char openState;		/* Used for opening a connection (see below) */

    gbuf_t *rbuf_mb;		/* message block for the recv buffer */
    gbuf_t *crbuf_mb;
    gbuf_t *sbuf_mb;		/* message block for the send buffer */
    gbuf_t *csbuf_mb;
    gbuf_t *attn_mb;		/* message block for the attention buffer */
    gbuf_t *deferred_mb;	/* message block deferred for later processing */
	
#ifdef NOT_USED
    char ioDone;		/* flag for when the adsp header is busy */
#endif
    char probeCntr;		/* # of probes we can miss (counts down) */
    char pktSendMax;		/* Max # of packets to send without an ack */
    char pktSendCnt;		/* # of packets sent so far */
	
    int sendStamp;		/* Time of last ackRequest */
    int timerSeq;		/* Seq # of char corresponding to above time stamp */
    short roundTrip;		/* Average Round-Trip time (in 6ths of a second) */
    short deviation;		/* deviation from roundTrip time */
    
    unsigned sData:1;		/* There's data in the send queue */
    unsigned waitingAck:1;	/* We're waiting for an ack packet */
    unsigned rData:1;		/* There's data in the receive queue */
    unsigned resentData:1;	/* True when we resend data due to timeout */
    unsigned sendDataAck:1;	/* True if he requested an ack */
    unsigned sendAttnAck:1;	/* Must send attn acknowlege */
    unsigned sendAttnData:1;	/* Must send attn data */
    unsigned callSend:1;	/* Must call CheckSend() */
    unsigned rbufFull:1;	/* We've closed our receive window. */
    unsigned noXmitFlow:1;	/* True stops incrementing # of xmit 
				 * packets to send in a row after receiving 
				 * an ack packet. */
    unsigned secureCCB:1;	/* True if this is a secure connection */
    unsigned removing:1;	/* There is a dspRemove pending */
    unsigned writeFlush:1;	/* Flush send queue even if # bytes to 
				 * send is less than send blocking. */
    unsigned delay:1;		/* do not complete commands until user
				 * *** NO LONGER USED IN KERNEL *** */
    ADSP_FRAME f;		/* Used to send every packet */
    ADSP_OPEN_DATA of;		/* Holds the data for the open exchange */
    gref_t *gref;			/* The queue associated with the CCB */
    gbuf_t *sp_mp;
    atlock_t lock;
    atlock_t lockClose;
    atlock_t lockRemove;
} CCB, *CCBPtr;


/*
 * Change order and die !!! --- See the receive open packet code
 */
#define O_STATE_NOTHING		0	/* Not opening */
#define O_STATE_LISTEN 		1	/* Listening for open request */
#define O_STATE_OPENWAIT 	2 	/* Sent Req, waiting for Ack to open 
				  	 * request */
#define O_STATE_ESTABLISHED 	3	/* Got Req, send Req+Ack,waiting Ack */
#define O_STATE_OPEN		4	/* Connection is open */

/*
* These bits are used in the sendCtl field to indicate what needs to be sent
*/
#define B_CTL_PROBE		0x0001
#define B_CTL_OREQ		0x0002
#define B_CTL_OACK		0x0004
#define B_CTL_OREQACK		0x0008
#define B_CTL_ODENY		0x0010
#define B_CTL_CLOSE		0x0020
#define B_CTL_FRESET		0x0040
#define B_CTL_FRESETACK		0x0080
#define	B_CTL_RETRANSMIT	0x0100


#define kProbeTimerType offsetof(CCB, ProbeTimer)
#define kFlushTimerType offsetof(CCB, FlushTimer)
#define kRetryTimerType offsetof(CCB, RetryTimer)
#define kAttnTimerType offsetof(CCB, AttnTimer)
#define kResetTimerType offsetof(CCB, ResetTimer)

/*
 * Used to manage the send receive queue
 */
typedef struct {
    short len;			/* # of bytes in this fragment */
    char flags;			/* See #define's below */
    char data[1];
} HDR, *HDRPtr;

#define	HDR_LEN	3		/* Yes, I know it really is 4 bytes long... */

#define F_GAP		0x03
#define F_EOM		0x04
#define F_WRAP		0x08
#define F_VALID		0x10
#define F_ENCRYPTED	0x20	/* %%% Needed ??? */
#define F_LAST		0x40	/* This is last block in buffer */


/* %%% Are these two used anymore? */
#define sbufPtr(y) (&sp->sbuf[((y) < sp->sbuflen) ? (y) : ((y) - sp->sbuflen)])
#define rbufPtr(y) (&sp->rbuf[((y) < sp->rbuflen) ? (y) : ((y) - sp->rbuflen)])

/* End Internal.h */

/* fron h/adsp_supp.h */

void	CallUserRoutine(CCBPtr sp);	/* (CCB FPTR sp); */


/*
 *	Add queue element to end of queue.  Pass Address of ptr to 
 *	1st element of queue
int	qAddToEnd(struct qlink **qhead, struct qlink *qelem);
 */
		/* (void FPTR FPTR qhead, void FPTR qelem); */

/*
 *	Hunt down a linked list of queue elements looking for an element with
 *	'data' at 'offset' bytes into the queue element.
 */
void *qfind_b(void *qhead, word offset, word data);
void *qfind_w(void *qhead, word offset, word data);
void *qfind_p(void *qhead, word offset, void *ptr);
void *qfind_o(void *qhead, word offset, void *ptr);
void *qfind_m(CCBPtr qhead, void *match, ProcPtr compare_fnx);


/*
 * Routines to handle sorted timer queues
 */
void InsertTimerElem(TimerElemPtr *qhead, TimerElemPtr t, int val);
void RemoveTimerElem(TimerElemPtr *qhead, TimerElemPtr t);
void TimerQueueTick(TimerElemPtr *qhead);

/* from h/adsp_global.h */

typedef struct {
	void *ccbList;		/* Ptr to list of connection control blocks */

	TimerElemPtr slowTimers; /* The probe timer list */
	TimerElemPtr fastTimers; /* The fast timer list */

	unsigned short lastCID;		/* Last connection ID assigned */
	char inTimer;		/* We're inside timer routine */
} GLOBAL;

extern GLOBAL adspGlobal;

/* Address of ptr to list of ccb's */
#define AT_ADSP_STREAMS ((CCB **)&(adspGlobal.ccbList))

#endif /* KERNEL_PRIVATE */
#endif /* __APPLE_API_OBSOLETE */

#endif /* _NETAT_ADSP_INTERNAL_H_ */
