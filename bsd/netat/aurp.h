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
 *	Copyright (c) 1996 Apple Computer, Inc. 
 *
 *		Created April 23, 1996, by Justin C. Walker
 *
 *	File: aurp.h
 */

#ifndef _NETAT_AURP_H_
#define	_NETAT_AURP_H_
#include <sys/appleapiopts.h>

/*
 * AURP device ioctl (I_STR) 'subcommands'
 */
#define AUC_CFGTNL	0	/* Configure Tunnels */
#define AUC_SHTDOWN	1	/* Shutdown AURP */
#define AUC_EXPNET	2	/* Configure exported networks */
#define AUC_HIDENET	3	/* Configure hidden netowrks */
#define AUC_UDPPORT	4	/* UPD Port number */
#define AUC_NETLIST	5	/* List of remote endpoints */
#define AUC_TIMER	6	/* Configured update interval timer */
#define AUC_ADDNET      7       /* Add remote endpoints */
#define AUC_ACCEPTALL   8       /* Accept all nets */
#define AUC_MAX         9       /* Maximun numbers of access nets */

/* Default AURP-over-UDP port */
#define AURP_SOCKNUM      387
#define AURP_MAXNETACCESS 64

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE

#define AURPCODE_REG                   0
#define AURPCODE_RTMPPKT               1
#define AURPCODE_DATAPKT               2
#define AURPCODE_AURPPROTO             3
#define AURPCODE_DEBUGINFO             10
#ifdef NOT_USED
#define AURPCODE_RTINFO 11 /* was used to set up pointers to the
			      routing table, the zone table, and 
			      several functions */
#endif
#define AURPCODE_RTUPDATE              12

#define AURPSTATE_Unconnected          0
#define AURPSTATE_Connected            1
#define AURPSTATE_WaitingForOpenRsp    2
#define AURPSTATE_WaitingForRIRsp      3
#define AURPSTATE_WaitingForTickleAck  4
#define AURPSTATE_WaitingForRIAck1     5
#define AURPSTATE_WaitingForRIAck2     6
#define AURPSTATE_WaitingForRIAck3     7

#define AURPCMD_RIReq                  1
#define AURPCMD_RIRsp                  2
#define AURPCMD_RIAck                  3
#define AURPCMD_RIUpd                  4
#define AURPCMD_RDReq                  5
#define AURPCMD_ZReq                   6
#define AURPCMD_ZRsp                   7
#define AURPCMD_OpenReq                8
#define AURPCMD_OpenRsp                9
#define AURPCMD_Tickle                 14
#define AURPCMD_TickleAck              15

#define AURPSUBCODE_ZoneInfo1          1
#define AURPSUBCODE_ZoneInfo2          2
#define AURPSUBCODE_GetZoneNets        3
#define AURPSUBCODE_GetDomainZoneList  4

#define AURPEV_Null                    0
#define AURPEV_NetAdded                1
#define AURPEV_NetDeleted              2
#define AURPEV_NetRouteChange          3
#define AURPEV_NetDistChange           4
#define AURPEV_NetZoneChange           5

#define AURP_Version                   1
#define AURP_ProbeRetryInterval        300
#define AURP_MaxTickleRetry            4
#define AURP_TickleRetryInterval       30
#define AURP_MaxRetry                  10
#define AURP_RetryInterval             3
#define AURP_UpdateRate                1
#define AURP_UDType                    0
#define AURP_UDNode                    1
#define AURP_UDSize                    2
#define AURP_FirstSeqNum               1
#define AURP_LastSeqNum                65535
#define AURP_MaxPktSize                1400
#define AURP_MaxNetAccess              64
#define AURP_NetHiden                  0x01

#define AURPERR_NormalConnectionClose  -1
#define AURPERR_RoutingLoopDetected    -2
#define AURPERR_ConnectionOutOfSync    -3
#define AURPERR_OptionNegotiationError -4
#define AURPERR_InvalidVersionNumber   -5
#define AURPERR_InsufficientResources  -6
#define AURPERR_AuthenticationError    -7

#define AURPFLG_NA    0x4000
#define AURPFLG_ND    0x2000
#define AURPFLG_NDC   0x1000
#define AURPFLG_ZC    0x0800
#define AURPFLG_RMA   0x4000
#define AURPFLG_HCRA  0x2000
#define AURPFLG_SZI   0x4000
#define AURPFLG_LAST  0x8000

/*
 * AURP state block
 */
typedef struct {
	unsigned char  get_zi;          /* get zone info flag */
	unsigned char  rem_node;        /* node id of a tunnel peer */
	unsigned char  tickle_retry;    /* tickle retry count */
	unsigned char  rcv_retry;       /* data receiver retry count */
	unsigned char  snd_state;       /* data sender state */
	unsigned char  rcv_state;       /* data receiver state */
	unsigned char  filler[2];
	unsigned short rcv_update_rate;
	unsigned short snd_next_entry;  /* next entry in RT */
	unsigned short rcv_env;
	unsigned short snd_sui;
	unsigned short rcv_connection_id;   /* data receiver connection id */
	unsigned short snd_connection_id;   /* data sender connection id */
	unsigned short rcv_sequence_number; /* data receiver sequence number */
	unsigned short snd_sequence_number; /* data sender sequence number */
	int   rcv_tmo;
	int   snd_tmo;
	gbuf_t *rsp_m;
	gbuf_t *upd_m;
} aurp_state_t;

/*
 * AURP protocol header
 */
typedef struct {
	unsigned short connection_id;
	unsigned short sequence_number;
	unsigned short command_code;
	unsigned short flags;
} aurp_hdr_t;

#ifdef AURP_SUPPORT

extern atlock_t aurpgen_lock;
extern gref_t *aurp_gref;
extern unsigned char dst_addr_cnt;
extern unsigned char net_access_cnt;
extern unsigned char net_export;
extern unsigned short rcv_connection_id;
extern int net_port;
extern int update_tmo;
extern aurp_state_t aurp_state[];
extern unsigned short net_access[];
#endif

struct myq
{	struct mbuf *q_head;
	struct mbuf *q_tail;
	int q_cnt;
};

#define LOCK_DECL(x)	atlock_t x

/*
 * Quandry: if we use a single socket, we have to rebind on each call.
 * If we use separate sockets per tunnel endpoint, we have to examine
 *  each one on wakeup.  What to do; what to do?
 */
struct aurp_global_t
{	int src_addr;		/* What's our IP address? */
	int udp_port;		/* Local UDP port */
	unsigned short net_access[AURP_MAXNETACCESS];
	long dst_addr[256];	/* Tunnel 'other ends', passed in from user */
	int pid;		/* Who are we? */
	struct socket *tunnel;	/* IP socket for all IP endpoints */
	int event;		/* Sleep queue anchor */
	int event_anchor;	/* Sleep queue anchor */
	atlock_t glock;		/* aurp_global lock */
	struct uio auio;	/* Dummy uio struct for soreceive() */
	/* Statistics */
	unsigned int toosmall;	/* size less than domain header, from UDP */
	unsigned int no_mbufs;	/* gbuf_to_mbuf failed */
	unsigned int no_gbufs;	/* mbuf_to_gbuf failed */
	unsigned int shutdown;	/* shutdown flag */
	unsigned int running;	/* running flag */
};

#define AE_ATALK	0x01	/* A/talk input event */
#define AE_UDPIP	0x02	/* UDP/IP input event */
#define AE_SHUTDOWN	0x04	/* Shutdown AURP process */
 
void aurp_wakeup __P((struct socket *, caddr_t, int));
struct mbuf *at_gbuf_to_mbuf __P((gbuf_t *));
gbuf_t *at_mbuf_to_gbuf __P((struct mbuf *, int));
int at_insert __P((gbuf_t *m, unsigned int type, unsigned int node));
int ddp_AURPfuncx __P((int code, void *param, unsigned char node));
int AURPinit __P((void));
int aurpd_start __P((void));
void atalk_to_ip __P((gbuf_t *m));
void AURPaccess __P((void));
void AURPshutdown __P((void));
void AURPiocack __P((gref_t *gref, gbuf_t *m));
void AURPiocnak __P((gref_t *gref, gbuf_t *m, int error));
void AURPsndZReq __P((aurp_state_t *state));
void AURPsndZRsp __P((aurp_state_t *state, gbuf_t *dat_m, int flag));
void AURPsndRIUpd __P((aurp_state_t *state));
void AURPsndRIReq __P((aurp_state_t *state));
void AURPsndRIAck __P((aurp_state_t *state, gbuf_t *m, unsigned short flags));
void AURPsndOpenReq __P((aurp_state_t *state));
void AURPsndRDReq __P((aurp_state_t *state));
void AURPrcvZReq __P((aurp_state_t *state, gbuf_t *m));
void AURPrcvZRsp __P((aurp_state_t *state, gbuf_t *m));
void AURPrcvRIUpd __P((aurp_state_t *state, gbuf_t *m));
void AURPrcvRIReq __P((aurp_state_t *state, gbuf_t *m));
void AURPrcvRIAck __P((aurp_state_t *state, gbuf_t *m));
void AURPrcvRIRsp __P((aurp_state_t *state, gbuf_t *m));
void AURPrcvOpenReq __P((aurp_state_t *state, gbuf_t *m));
void AURPrcvOpenRsp __P((aurp_state_t *state, gbuf_t *m));
void AURPrcvTickle __P((aurp_state_t *state, gbuf_t *m));
void AURPrcvTickleAck __P((aurp_state_t *state, gbuf_t *m));
void AURPrcvRDReq __P((aurp_state_t *state, gbuf_t *m));
void AURPfreemsg __P((gbuf_t *m));
void AURPrtupdate __P((RT_entry *entry, unsigned char ev));
void AURPsend __P((gbuf_t *mdata, int type, int node));
void AURPcleanup __P((aurp_state_t *state));
void AURPpurgeri __P((unsigned char node));
int AURPgetri __P((short next_entry, unsigned char *buf, short *len));
int AURPsetri __P((unsigned char node, gbuf_t *m));
int AURPupdateri __P((unsigned char node, gbuf_t *m));

/* AURP header for IP tunneling */
typedef struct aurp_domain
{	char  dst_length;
	char  dst_authority;
	short dst_distinguisher;
	long  dst_address;
	char  src_length;
	char  src_authority;
	short src_distinguisher;
	long  src_address;
	short version;
	short reserved;
	short type;
} aurp_domain_t;

/* AURP/domain header constants */
#define AUD_Version	0x1
#define AUD_Atalk	0x2
#define AUD_AURP	0x3

/* IP domain identifier constants */
#define IP_LENGTH		7
#define IP_AUTHORITY		1
#define IP_DISTINGUISHER	0
/* Need this because the )(*&^%$#@ compiler rounds up the size */
#define IP_DOMAINSIZE		22

/****### LD 9/26/97*/
extern struct aurp_global_t aurp_global;
#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* _NETAT_AURP_H_ */
