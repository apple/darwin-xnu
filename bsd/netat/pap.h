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
 *
 * ORIGINS: 82
 *
 * (C) COPYRIGHT Apple Computer, Inc. 1992-1996
 * All Rights Reserved
 *
 */                                                                   

/* Definitions for ATP protocol and streams module, per 
 * AppleTalk Transaction Protocol documentation from
 * `Inside AppleTalk', July 14, 1986.
 */

#ifndef _NETAT_PAP_H_
#define _NETAT_PAP_H_
#include <sys/appleapiopts.h>

#ifdef __APPLE_API_OBSOLETE

#define  AT_PAP_DATA_SIZE	      512    /* Maximum PAP data size */
#define  AT_PAP_STATUS_SIZE	      255    /* Maximum PAP status length */
#define  PAP_TIMEOUT		      120

/* PAP packet types */

#define  AT_PAP_TYPE_OPEN_CONN        0x01   /* Open-Connection packet */
#define  AT_PAP_TYPE_OPEN_CONN_REPLY  0x02   /* Open-Connection-Reply packet */
#define  AT_PAP_TYPE_SEND_DATA        0x03   /* Send-Data packet */
#define  AT_PAP_TYPE_DATA             0x04   /* Data packet */
#define  AT_PAP_TYPE_TICKLE           0x05   /* Tickle packet */
#define  AT_PAP_TYPE_CLOSE_CONN       0x06   /* Close-Connection packet */
#define  AT_PAP_TYPE_CLOSE_CONN_REPLY 0x07   /* Close-Connection-Reply pkt */
#define  AT_PAP_TYPE_SEND_STATUS      0x08   /* Send-Status packet */
#define  AT_PAP_TYPE_SEND_STS_REPLY   0x09   /* Send-Status-Reply packet */
#define  AT_PAP_TYPE_READ_LW	      0x0A   /* Read LaserWriter Message */


/* PAP packet structure */

typedef struct {
        u_char     at_pap_connection_id;
        u_char	   at_pap_type;
        u_char     at_pap_sequence_number[2];
        u_char	   at_pap_responding_socket;
        u_char     at_pap_flow_quantum;
        u_char     at_pap_wait_time_or_result[2];
        u_char     at_pap_buffer[AT_PAP_DATA_SIZE];
} at_pap;


/* ioctl definitions */

#define	AT_PAP_SETHDR		(('~'<<8)|0)
#define	AT_PAP_READ		(('~'<<8)|1)
#define	AT_PAP_WRITE		(('~'<<8)|2)
#define	AT_PAP_WRITE_EOF	(('~'<<8)|3)
#define	AT_PAP_WRITE_FLUSH	(('~'<<8)|4)
#define	AT_PAP_READ_IGNORE	(('~'<<8)|5)
#define	AT_PAPD_SET_STATUS	(('~'<<8)|40)
#define	AT_PAPD_GET_NEXT_JOB	(('~'<<8)|41)

extern	char	at_pap_status[];
extern  char   *pap_status ();

#define	NPAPSERVERS	10	/* the number of active PAP servers/node */
#define	NPAPSESSIONS	40	/* the number of active PAP sockets/node */

#define AT_PAP_HDR_SIZE	(DDP_X_HDR_SIZE + ATP_HDR_SIZE)

#define	 ATP_DDP_HDR(c)	((at_ddp_t *)(c))

#define PAP_SOCKERR 	"Unable to open PAP socket"
#define P_NOEXIST 	"Printer not found"
#define P_UNREACH	"Unable to establish PAP session"

struct pap_state {
	u_char pap_inuse;	/* true if this one is allocated */
	u_char pap_tickle; 	/* true if we are tickling the other end */
	u_char pap_request; 	/* bitmap from a received request */
	u_char pap_eof;		/* true if we have received an EOF */
	u_char pap_eof_sent; 	/* true if we have sent an EOF */
	u_char pap_sent; 	/* true if we have sent anything (and
				   therefore may have to send an eof
				   on close) */
	u_char pap_error; 	/* error message from read request */
	u_char pap_timer; 	/* a timeout is pending */
	u_char pap_closing; 	/* the link is closing and/or closed */
	u_char pap_request_count; /* number of outstanding requests */
	u_char pap_req_timer; 	/* the request timer is running */
	u_char pap_ending; 	/* we are waiting for atp to flush */
	u_char pap_read_ignore; /* we are in 'read with ignore' mode */

	u_char pap_req_socket;
	at_inet_t pap_to;
	int pap_flow;

	u_short pap_send_count; /* the sequence number to send on the
				   next send data request */
	u_short pap_rcv_count; 	/* the sequence number expected to
				   receive on the next request */
	u_short pap_tid; 	/* ATP transaction ID for responses */
	u_char  pap_connID; 	/* our connection ID */

 	int pap_ignore_id;	/* the transaction ID for read ignore */
	int pap_tickle_id;	/* the transaction ID for tickles */
};

#endif /* __APPLE_API_OBSOLETE */
#endif /* _NETAT_PAP_H_ */
