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
/*
 *
 * ORIGINS: 82
 *
 * (C) COPYRIGHT Apple Computer, Inc. 1992-1996
 * All Rights Reserved
 *
 */                                                                   

#ifndef _NETAT_ADSP_H_
#define _NETAT_ADSP_H_
#include <sys/appleapiopts.h>
/* ADSP flags for read, write, and close routines */

#define	ADSP_EOM	0x01	/* Sent or received EOM with data */
#define ADSP_FLUSH	0x02	/* Send all data in send queue */
#define	ADSP_WAIT	0x04	/* Graceful close, wait 'til snd queue emptys */


/* ADSP events to be fielded by the user event handler */

#define	ADSP_EV_ATTN 	0x02	/* Attention data recvd. */
#define	ADSP_EV_RESET	0x04	/* Forward reset recvd. */
#define	ADSP_EV_CLOSE	0x08	/* Close advice recvd. */


/* ADSP packet control codes */

#define ADSP_PROBEACK 0			/* Probe or acknowledgement */
#define ADSP_OPENCONREQUEST 1		/* Open connection request */
#define ADSP_OPENCONACK 2		/* Open connection acknowledgement */
#define ADSP_OPENCONREQACK 3		/* Open connection request + ack */
#define ADSP_OPENCONDENIAL 4		/* Open connection denial */
#define ADSP_CLOSEADVICE 5		/* Close connection advice */
#define ADSP_FORWARDRESET 6		/* Forward reset */
#define ADSP_FORWARDRESETACK 7		/* Forward reset acknowledgement */
#define ADSP_RETRANSADVICE 8		/* Retransmit advice */


/* Miscellaneous constants */

#define ADSP_MAXDATA		572	/* Maximum data bytes in ADSP packet */
#define ADSP_MAXATTNDATA	570	/* Maximum data bytes in attn msg */
#define ADSP_DDPTYPE		7	/* DDP protocol type for ADSP */
#define ADSP_VERSION		0x0100	/* ADSP version */


/* Some additional ADSP error codes */

#define	EQUEWASEMP	10001
#define EONEENTQUE	10002
#define	EQUEBLOCKED	10003
#define	EFWDRESET	10004
#define	EENDOFMSG	10005
#define	EADDRNOTINUSE	10006



/* Tuning Parameter Block */

struct tpb {
   unsigned Valid : 1;			/* Tuning parameter block is valid */
   unsigned short TransThresh;		/* Transmit threshold */
   unsigned TransTimerIntrvl;		/* Transmit timer interval */
   unsigned short SndWdwCloThresh;	/* Send window closing threshold */
   unsigned SndWdwCloIntrvl;		/* Send window closed interval */
   unsigned char SndWdwCloBckoff;	/* Send window closed backoff rate */
   unsigned ReTransIntrvl;		/* Retransmit interval */
   unsigned char ReTransBckoff;		/* Retransmit backoff rate */
   unsigned RestartIntrvl;		/* Restart sender interval */
   unsigned char RestartBckoff;		/* Restart sender backoff rate */
   unsigned SndQBufSize;		/* Send queue buffer size */
   unsigned short RcvQMaxSize;		/* Maximum size of the receive queue */
   unsigned short RcvQCpyThresh;	/* Receive queue copy threshold */
   unsigned FwdRstIntrvl;		/* Forward reset interval */
   unsigned char FwdRstBckoff;		/* Forward reset backoff rate */
   unsigned AttnIntrvl;			/* Retransmit attn msg interval */
   unsigned char AttnBckoff;		/* Retransmit attn msg backoff rate */
   unsigned OpenIntrvl;			/* Retransmit open request interval */
   unsigned char OpenMaxRetry;		/* Open request maximum retrys */
   unsigned char RetransThresh;		/* Retransmit advice threshold */
   unsigned ProbeRetryMax;		/* Maximum number of probes */
   unsigned SndByteCntMax;		/* Maximum number bytes in send queue */
};


/* Tuning Parameter Tags */

#define	ADSP_TRANSTHRESH	 1	/* Transmit threshold */
#define	ADSP_TRANSTIMERINTRVL	 2	/* Transmit timer interval */
#define	ADSP_SNDWDWCLOTHRESH	 3	/* Send window closing threshold */
#define	ADSP_SNDWDWCLOINTRVL	 4	/* Send window closed interval */
#define	ADSP_SNDWDWCLOBCKOFF	 5	/* Send window closed backoff rate */
#define	ADSP_RETRANSINTRVL	 6	/* Retransmit interval */
#define	ADSP_RETRANSBCKOFF	 7	/* Retransmit backoff rate */
#define	ADSP_RESTARTINTRVL	 8	/* Restart sender interval */
#define	ADSP_RESTARTBCKOFF	 9	/* Restart sender backoff rate */
#define	ADSP_SNDQBUFSIZE	 10	/* Send queue buffer size */
#define	ADSP_RCVQMAXSIZE	 11	/* Receive queue maximum size */
#define	ADSP_RCVQCPYTHRESH	 12	/* Receive queue copy threshold */
#define	ADSP_FWDRSTINTRVL	 13	/* Forward reset retransmit interval */
#define	ADSP_FWDRSTBCKOFF	 14	/* Forward reset backoff rate */
#define	ADSP_ATTNINTRVL		 15	/* Rexmit attention message interval */
#define	ADSP_ATTNBCKOFF		 16	/* Attention message backoff rate */
#define	ADSP_OPENINTRVL		 17	/* Retransmit open request interval */
#define	ADSP_OPENMAXRETRY	 18	/* Open request max retrys */
#define	ADSP_RETRANSTHRESH	 19	/* Retransmit advice threshold */
#define	ADSP_PROBERETRYMAX	 20
#define	ADSP_SNDBYTECNTMAX	 21

#define TuneParamCnt 21			/* The number of tuning parameters */

/* Connection Status Tags */

#define	ADSP_STATE		 1	/* The connection state */
#define	ADSP_SNDSEQ		 2	/* Send sequence number */
#define	ADSP_FIRSTRTMTSEQ	 3	/* First retransmit sequence number */
#define	ADSP_SNDWDWSEQ	  	 4	/* Send window sequence number */
#define	ADSP_RCVSEQ		 5	/* Receive sequence number */
#define	ADSP_ATTNSNDSEQ	 	 6	/* Attn msg send sequence number */
#define	ADSP_ATTNRCVSEQ	 	 7	/* Attn msg receive sequence number */
#define	ADSP_RCVWDW		 8	/* Receive window size */
#define	ADSP_ATTNMSGWAIT	 9	/* Attn msg is in the receive queue */

#define ConStatTagCnt 9			/* Number of connection status tags */

#define	ADSP_INVALID	 	0       /* Invalid connection control block */
#define	ADSP_LISTEN	 	1       /* Waiting for an open con req */
#define	ADSP_OPENING	 	2     	/* No state info, sending open req */
#define	ADSP_MYHALFOPEN		4   	/* His state info, sending open req */
#define	ADSP_HISHALFOPEN	8  	/* He has my state info, sndng op req */
#define	ADSP_OPEN	 	16     	/* Connection is operational */
#define	ADSP_TORNDOWN	 	32     	/* Probe timer has expired 4 times */
#define	ADSP_CLOSING	 	64	/* Client close, emptying send Queues */
#define	ADSP_CLOSED	 	128	/* Close adv rcvd, emptying rcv Queues */

/* Management Counters */

#define	ADSP_ATTNACKRCVD	 1	/* Attn msg ack received */
#define	ADSP_ATTNACKACPTD	 2	/* Attn msg ack accepted */
#define	ADSP_PROBERCVD	 	 3	/* Probe received */
#define	ADSP_ACKRCVD		 4	/* Explicit ack msg received */
#define	ADSP_FWDRSTRCVD	 	 5	/* Forward reset received */
#define	ADSP_FWDRSTACPTD	 6	/* Forward reset accepted */
#define	ADSP_FWDRSTACKRCVD	 7	/* Forward reset ack received */
#define	ADSP_FWDRSTACKACPTD	 8	/* Forward reset ack accepted */
#define	ADSP_ATTNRCVD		 9	/* Attn msg received */
#define	ADSP_ATTNACPTD	   	 10	/* Attn msg accepted */
#define	ADSP_DATARCVD		 11	/* Data msg received */
#define	ADSP_DATAACPTD	  	 12	/* Data msg Accepted */
#define	ADSP_ACKFIELDCHKD	 13	/* Ack field checked */
#define	ADSP_ACKNRSFIELDACPTD	 14	/* Next receive seq field accepted */
#define	ADSP_ACKSWSFIELDACPTD	 15	/* Send window seq field accepted */
#define	ADSP_ACKREQSTD	 	 16	/* Ack requested */
#define	ADSP_LOWMEM		 17	/* Low memory */
#define	ADSP_OPNREQEXP	 	 18	/* Open request timer expired */
#define	ADSP_PROBEEXP	  	 19	/* Probe timer expired */
#define	ADSP_FWDRSTEXP	 	 20	/* Forward reset timer expired */
#define	ADSP_ATTNEXP	 	 21	/* Attention timer expired */
#define	ADSP_TRANSEXP	         22	/* Transmit timer expired */
#define	ADSP_RETRANSEXP	 	 23	/* Retransmit timer expired */
#define	ADSP_SNDWDWCLOEXP	 24	/* Send window closed timer expired */
#define	ADSP_RESTARTEXP	 	 25	/* Restart sender timer expired */
#define	ADSP_RESLOWEXP	 	 26	/* Resources are low timer expired */
#define	ADSP_RETRANSRCVD	 27	/* Retransmit advice received */

#define	InfoTagCnt		 27

/* Length of the parameter and status lists */

#define	ADSP_DEFLEN	 (TuneParamCnt * 6 + 1)
#define	ADSP_STALEN	 (ConStatTagCnt * 6 + 1)
#define	ADSP_INFOLEN	 (InfoTagCnt * 6 + 1)

/* from h/ADSP.h */

/* result codes */

#define controlErr -17          /*I/O System Errors*/

#define errENOBUFS	-1281
#define	errRefNum	-1280	/* bad connection refNum */
#define	errAborted	-1279	/* control call was aborted */
#define	errState	-1278	/* bad connection state for this operation */
#define	errOpening	-1277	/* open connection request failed */
#define	errAttention	-1276	/* attention message too long */
#define	errFwdReset	-1275	/* read terminated by forward reset */
#define errDSPQueueSize	-1274	/* DSP Read/Write Queue Too small */
#define errOpenDenied	-1273	/* open connection request was denied */

/* control codes */

#define	dspInit		255	/* create a new connection end */
#define	dspRemove	254	/* remove a connection end */
#define	dspOpen		253	/* open a connection */
#define	dspClose	252	/* close a connection */
#define	dspCLInit	251	/* create a connection listener */
#define	dspCLRemove	250	/* remove a connection listener */
#define	dspCLListen	249	/* post a listener request */
#define	dspCLDeny	248	/* deny an open connection request */
#define	dspStatus	247	/* get status of connection end */
#define	dspRead		246	/* read data from the connection */
#define	dspWrite	245	/* write data on the connection */
#define	dspAttention	244	/* send an attention message */
#define	dspOptions	243	/* set connection end options */
#define	dspReset	242	/* forward reset the connection */
#define	dspNewCID	241	/* generate a cid for a connection end */


/* connection opening modes */

#define	ocRequest	1	/* request a connection with remote */
#define	ocPassive	2	/* wait for a connection request from remote */
#define	ocAccept	3	/* accept request as delivered by listener */
#define	ocEstablish	4	/* consider connection to be open */


/* connection end states */

#define	sListening	1	/* for connection listeners */
#define	sPassive	2	/* waiting for a connection request from remote */
#define	sOpening	3	/* requesting a connection with remote */
#define	sOpen		4	/* connection is open */
#define	sClosing	5	/* connection is being torn down */
#define	sClosed		6	/* connection end state is closed */



/* client event flags */

#define	eClosed		0x80	/* received connection closed advice */
#define	eTearDown	0x40	/* connection closed due to broken connection */
#define	eAttention	0x20	/* received attention message */
#define	eFwdReset	0x10	/* received forward reset advice */

/* miscellaneous constants  */

#define	attnBufSize	570	/* size of client attention buffer */
#define	minDSPQueueSize	100	/* Minimum size of receive or send Queue */
#define defaultDSPQS	16384	/* random guess */
#define RecvQSize	defaultDSPQS
#define SendQSize	defaultDSPQS

/* *** Seems to be a problem in Mac OS X too *** */
/* Solaris defines u as (curproc->p_user) 
#if defined(u)
#undef u
#endif
*/

typedef long (*ProcPtr)();
typedef ProcPtr *ProcHandle;
typedef char *Ptr;
typedef Ptr *Handle;

/* connection control block */

struct TRCCB {
    u_char *ccbLink;	/* link to next ccb */
    u_short refNum;	/* user reference number */
    u_short state;	/* state of the connection end */
    u_char userFlags;	/* flags for unsolicited connection events */
    u_char localSocket;	/* socket number of this connection end */
    at_inet_t remoteAddress;	/* internet address of remote end */
    u_short attnCode;	/* attention code received */
    u_short attnSize;	/* size of received attention data */
    u_char *attnPtr;	/* ptr to received attention data */
    u_char reserved[220]; /* for adsp internal use */
};

typedef struct TRCCB TRCCB;
typedef TRCCB *TPCCB;

/* init connection end parameters */

struct TRinitParams {
    TPCCB ccbPtr;		/* pointer to connection control block */
    ProcPtr userRoutine;	/* client routine to call on event */
    u_char *sendQueue;		/* client passed send queue buffer */
    u_char *recvQueue;		/* client passed receive queue buffer */
    u_char *attnPtr;		/* client passed receive attention buffer */
    u_short sendQSize;		/* size of send queue (0..64K bytes) */
    u_short recvQSize;		/* size of receive queue (0..64K bytes) */
    u_char localSocket;		/* local socket number */
};

typedef struct TRinitParams TRinitParams;

/* open connection parameters */

struct TRopenParams {
    u_short localCID;		/* local connection id */
    u_short remoteCID;		/* remote connection id */
    at_inet_t remoteAddress;	/* address of remote end */
    at_inet_t filterAddress;	/* address filter */
    unsigned long sendSeq;	/* local send sequence number */
    u_long recvSeq;		/* receive sequence number */
    u_long attnSendSeq;		/* attention send sequence number */
    u_long attnRecvSeq;		/* attention receive sequence number */
    u_short sendWindow;		/* send window size */
    u_char ocMode;		/* open connection mode */
    u_char ocInterval;		/* open connection request retry interval */
    u_char ocMaximum;		/* open connection request retry maximum */
};

typedef struct TRopenParams TRopenParams;

/* close connection parameters */

struct TRcloseParams 	{
    u_char abort;		/* abort connection immediately if non-zero */
};

typedef struct TRcloseParams TRcloseParams;

/* client status parameter block */

struct TRstatusParams {
    TPCCB ccbPtr;		/* pointer to ccb */
    u_short sendQPending;	/* pending bytes in send queue */
    u_short sendQFree;		/* available buffer space in send queue */
    u_short recvQPending;	/* pending bytes in receive queue */
    u_short recvQFree;		/* available buffer space in receive queue */
};
	
typedef struct TRstatusParams TRstatusParams;

/* read/write parameter block */

struct TRioParams {
    u_short reqCount;		/* requested number of bytes */
    u_short actCount;		/* actual number of bytes */
    u_char *dataPtr;		/* pointer to data buffer */
    u_char eom;			/* indicates logical end of message */
    u_char flush;		/* send data now */
    u_char dummy[2];            /*### LD */
};

typedef struct TRioParams TRioParams;

/* attention parameter block */

struct TRattnParams {
    u_short attnCode;		/* client attention code */
    u_short attnSize;		/* size of attention data */
    u_char *attnData;		/* pointer to attention data */
    u_char attnInterval;	/* retransmit timer in 10-tick intervals */
    u_char dummy[3];		/* ### LD */
};

typedef struct TRattnParams TRattnParams;

/* client send option parameter block */

struct TRoptionParams {
    u_short sendBlocking;	/* quantum for data packets */
    u_char sendTimer;		/* send timer in 10-tick intervals */
    u_char rtmtTimer;		/* retransmit timer in 10-tick intervals */
    u_char badSeqMax;		/* threshold for sending retransmit advice */
    u_char useCheckSum;		/* use ddp packet checksum */
    u_short filler;		/* ### LD */
    int newPID;			/* ### Temp for backward compatibility 02/11/94 */
};

typedef struct TRoptionParams TRoptionParams;

/* new cid parameters */

struct TRnewcidParams {
    u_short newcid;		/* new connection id returned */
};

typedef struct TRnewcidParams TRnewcidParams;

union adsp_command {
	TRinitParams initParams; /* dspInit, dspCLInit */
	TRopenParams openParams; /* dspOpen, dspCLListen, dspCLDeny */
	TRcloseParams closeParams; /* dspClose, dspRemove */
	TRioParams ioParams;	/* dspRead, dspWrite, dspAttnRead */
	TRattnParams attnParams; /* dspAttention */
	TRstatusParams statusParams; /* dspStatus */
	TRoptionParams optionParams; /* dspOptions */
	TRnewcidParams newCIDParams; /* dspNewCID */
};

/* ADSP CntrlParam ioQElement */

struct DSPParamBlock {
    struct QElem *qLink;
    short qType;
    short ioTrap;
    Ptr ioCmdAddr;
    ProcPtr ioCompletion;
    short ioResult;
    char *ioNamePtr;
    short ioVRefNum;
    short ioCRefNum;		/* adsp driver refNum */
    short csCode;		/* adsp driver control code */
    long qStatus;		/* adsp internal use */
    u_short ccbRefNum;		/* connection end refNum */
    union adsp_command u;
};
	
typedef struct DSPParamBlock DSPParamBlock;
typedef DSPParamBlock *DSPPBPtr;

struct adspcmd {
    struct adspcmd *qLink;
    u_int ccbRefNum;
    caddr_t ioc;
#ifdef KERNEL
    gref_t *gref;
    gbuf_t *mp;
#else
    void *gref;
    void *mp;
#endif
    short ioResult;
    u_short ioDirection;
    short csCode;
    u_short socket;
    union adsp_command u;
};

/* from h/adsp_frames.h */

#ifdef NOT_USED
/*
 * LAP Frame Information
 */

typedef struct {
  u_char     lap_dest;
  u_char     lap_src;
  u_char     lap_type;
  u_char     lap_data[1];
} LAP_FRAME;

#define LAP_FRAME_LEN     3

#define MAX_FRAME_SIZE    603

#define LAP_DDP           0x01
#define LAP_DDPX          0x02

typedef struct {
  ua_short   ddp_length;             /* length of ddp fields        */
  u_char     ddp_dest;               /* destination socket          */
  u_char     ddp_source;             /* source socket               */
  u_char     ddp_type;               /* protocol type               */
  u_char     ddp_data[1];            /* data field                  */
} DDP_FRAME;

#define DDPS_FRAME_LEN     5
#endif NOT_USED

typedef struct {
  ua_short   ddpx_length;            /* length and hop count        */
  ua_short   ddpx_cksm;              /* checksum                    */
  at_net     ddpx_dnet;              /* destination network number  */
  at_net     ddpx_snet;              /* source network number       */
  u_char     ddpx_dnode;             /* destination node            */
  u_char     ddpx_snode;             /* source node                 */
  u_char     ddpx_dest;              /* destination socket          */
  u_char     ddpx_source;            /* source socket               */
  u_char     ddpx_type;              /* protocol type               */
  u_char     ddpx_data[1];           /* data field                  */
} DDPX_FRAME;

#define DDPL_FRAME_LEN     13

#ifdef NOT_USED
typedef struct {
  u_char     nbp_ctrl_cnt;           /* control and tuple count     */
  u_char     nbp_id;                 /* enquiry/reply id            */
  u_char     nbp_data[1];            /* tuple space                 */
} NBP_FRAME;

#define NBP_TYPE_MASK     0xf0     /* mask of ctrl_cnt field      */
#define NBP_CNT_MASK      0x0f     /* mask for number of tuples   */
#define NBP_BROADCAST     0x10     /* internet lookup             */
#define NBP_LOOKUP        0x20     /* lookup request              */
#define NBP_REPLY         0x30     /* response to lookup          */

typedef struct {
  u_char     atp_control;            /* control field               */
  u_char     atp_map;                /* bitmap for acknowlegement   */
  ua_short   atp_tid;                /* transaction id              */
  union
  {
      u_char     b[4];               /* user u_chars                  */
      ua_long    dw;
  } atp_ub;
  u_char     atp_data[1];            /* data field                  */
} ATP_FRAME;

#define ATP_FRAME_LEN      8

#define ATP_TREQ          0x40     /* transaction request         */
#define ATP_TRESP         0x80     /* response packet             */
#define ATP_TREL          0xc0     /* transaction release packet  */
#define ATP_XO            0x20     /* exactly once flag           */
#define ATP_EOM           0x10     /* end of message flag         */
#define ATP_STS           0x08     /* send transaction status     */

#define ATP_TYPE(x)       ((x)->atp_control & 0xc0)

typedef struct {
  at_net     net1;
  u_char     zonename[33];
} ZIP_1;

typedef struct {
  at_net     net1;
  at_net     net2;
  u_char     zonename[33];
} ZIP_2;

typedef struct {
  u_char     zip_command;             /* zip command number          */
  u_char     flags;                   /* Bit-mapped                  */
  union
  {
     ZIP_1 o;                       /* Packet has one net number   */
     ZIP_2 r;                       /* Packet has cable range      */
  } u;
} ZIP_FRAME;

/* Flags in the ZIP GetNetInfo & NetInfoReply buffer  */

#define ZIPF_BROADCAST     0x80
#define ZIPF_ZONE_INVALID  0x80
#define ZIPF_USE_BROADCAST 0x40
#define ZIPF_ONE_ZONE      0x20

#define ZIP_QUERY          1        /* ZIP Commands in zip frames  */
#define ZIP_REPLY          2
#define ZIP_TAKEDOWN       3
#define ZIP_BRINGUP        4
#define ZIP_GETNETINFO     5
#define ZIP_NETINFOREPLY   6
#define ZIP_NOTIFY         7

#define ZIP_GETMYZONE      7        /* ZIP commands in atp user u_chars[0]  */
#define ZIP_GETZONELIST    8
#define ZIP_GETLOCALZONES  9
#define ZIP_GETYOURZONE    10       

/*
 * Response to Reponder Request type #1.
 *
 * The first 4 u_chars are actually the 4 ATP user u_chars
 * Following this structure are 4 PASCAL strings:
 *    System Version String. (max 127)
 *    Finder Version String. (max 127)
 *    LaserWriter Version String. (max 127)
 *    AppleShare Version String. (max 24)
 */
typedef struct
{
   u_char  UserU_Chars[2];
   ua_short  ResponderVersion;
   ua_short  AtalkVersion;
   u_char  ROMVersion;
   u_char  SystemType;
   u_char  SystemClass;
   u_char  HdwrConfig;
   ua_short  ROM85Version;
   u_char  ResponderLevel;
   u_char  ResponderLink;
   u_char  data[1];
} RESPONDER_FRAME;
#endif NOT_USED

/*
 * ADSP Frame
 */
typedef struct {
   ua_short CID;
   ua_long pktFirstByteSeq;
   ua_long pktNextRecvSeq;
   ua_short  pktRecvWdw;
   u_char descriptor;		/* Bit-Mapped */
   u_char data[1];
} ADSP_FRAME, *ADSP_FRAMEPtr;

#define ADSP_FRAME_LEN     13

#define ADSP_CONTROL_BIT   0x80
#define ADSP_ACK_REQ_BIT   0x40
#define ADSP_EOM_BIT       0x20
#define ADSP_ATTENTION_BIT 0x10
#define ADSP_CONTROL_MASK  0x0F

#define ADSP_CTL_PROBE        0x00 /* Probe or acknowledgement */
#define ADSP_CTL_OREQ         0x01 /* Open Connection Request */
#define ADSP_CTL_OACK         0x02 /* Open Request acknowledgment */
#define ADSP_CTL_OREQACK      0x03 /* Open Request and acknowledgement */
#define ADSP_CTL_ODENY        0x04 /* Open Request denial */
#define ADSP_CTL_CLOSE        0x05 /* Close connection advice */
#define ADSP_CTL_FRESET       0x06 /* Forward Reset */
#define ADSP_CTL_FRESET_ACK   0x07 /* Forward Reset Acknowledgement */
#define ADSP_CTL_RETRANSMIT   0x08 /* Retransmit advice	*/

typedef struct {
   ua_short  version;		/* Must be in network byte order */
   ua_short  dstCID;		/* */
   ua_long pktAttnRecvSeq;		/* Must be in network byte order */
} ADSP_OPEN_DATA, *ADSP_OPEN_DATAPtr;

#define ADSP_OPEN_FRAME_LEN   8

#define ADSP_MAX_DATA_LEN		572

/* from h/adsp_ioctl.h */

/*
 * Defines that correspond to atlog.h in the N & C Appletalk
 * sources.
 */

#define AT_MID_ADSP	212

/* Streams ioctl definitions */

#define ADSP_IOCTL(i)     ((i>>8) == AT_MID_ADSP)
#define ADSPATTNREAD	((AT_MID_ADSP<<8) | 254) /* read attention data */
#define	ADSPOPEN 	((AT_MID_ADSP<<8) | 253) /* open a connection */
#define	ADSPCLOSE 	((AT_MID_ADSP<<8) | 252) /* close a connection */
#define	ADSPCLINIT 	((AT_MID_ADSP<<8) | 251) /* create a conn listener */
#define	ADSPCLREMOVE 	((AT_MID_ADSP<<8) | 250) /* remove a conn listener */
#define	ADSPCLLISTEN 	((AT_MID_ADSP<<8) | 249) /* post a listener request */
#define	ADSPCLDENY 	((AT_MID_ADSP<<8) | 248) /* deny an open connection request */
#define	ADSPSTATUS 	((AT_MID_ADSP<<8) | 247) /* get status of conn end */
#define	ADSPREAD 	((AT_MID_ADSP<<8) | 246) /* read data from conn */
#define	ADSPWRITE 	((AT_MID_ADSP<<8) | 245) /* write data on the conn */
#define	ADSPATTENTION 	((AT_MID_ADSP<<8) | 244) /* send attention message */
#define	ADSPOPTIONS 	((AT_MID_ADSP<<8) | 243) /* set conn end options */
#define	ADSPRESET 	((AT_MID_ADSP<<8) | 242) /* forward reset connection */
#define	ADSPNEWCID 	((AT_MID_ADSP<<8) | 241) /* generate a cid conn end */
#define ADSPBINDREQ	((AT_MID_ADSP<<8) | 240)
#define ADSPGETSOCK	((AT_MID_ADSP<<8) | 239)
#define ADSPGETPEER	((AT_MID_ADSP<<8) | 238)

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE

/* from h/adsp_adsp.h */

/* Definitions from strgeneric.h (on AIX?) */
#define STR_IGNORE	0
#define STR_PUTNEXT	1
#define STR_PUTBACK	2
#define STR_QTIME	(HZ >> 3)

extern int adspInit();
extern int adspOpen();
extern int adspCLListen();
extern int adspClose();
extern int adspCLDeny();
extern int adspStatus();
extern int adspRead();
extern int adspWrite();
extern int adspAttention();
extern int adspOptions();
extern int adspReset();
extern int adspNewCID();
extern int adspPacket();


struct adsp_debug {
    int ad_time;
    int ad_seq;
    int ad_caller;
    int ad_descriptor;
    int ad_bits;
    short ad_sendCnt;
    short ad_sendMax;
    int ad_maxSendSeq;
    int ad_sendWdwSeq;
};

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* _NETAT_ADSP_H_ */
