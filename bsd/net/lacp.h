/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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
 * lacp.h
 * - definitions for the Link Aggregation Control Protocol (LACP) and
 *   the Link Aggregation Marker Protocol
 */

/* 
 * Modification History
 *
 * May 14, 2004	Dieter Siegmund (dieter@apple.com)
 * - created
 */

#ifndef _NET_LACP_H_
#define	_NET_LACP_H_

#include <sys/types.h>

/**
 ** Link Aggregation Control Protocol (LACP) definitions
 **/
#define LACPDU_VERSION_1		1

#define LACPDU_TLV_TYPE_TERMINATOR	0x00
#define LACPDU_TLV_TYPE_ACTOR		0x01
#define LACPDU_TLV_TYPE_PARTNER	0x02
#define LACPDU_TLV_TYPE_COLLECTOR	0x03

#define LACPDU_ACTOR_TLV_LENGTH	20
#define LACPDU_PARTNER_TLV_LENGTH	20
#define LACPDU_COLLECTOR_TLV_LENGTH	16

typedef u_char lacp_actor_partner_state;
typedef u_int16_t lacp_key;
typedef u_int16_t lacp_system_priority, lacp_port_priority, lacp_port;
typedef u_int16_t lacp_collector_max_delay;
typedef struct {
    u_char 	system_id[6];
} lacp_system, *lacp_system_ref;

/*
 * LACP Actor/Partner TLV 
 */
typedef struct lacp_actor_partner_tlv_s {
    u_char	lap_tlv_type;		/* 0x01 or 0x02 */
    u_char	lap_length;		/* 20 */
    u_char	lap_system_priority[2];
    u_char	lap_system[6];
    u_char	lap_key[2];
    u_char	lap_port_priority[2];
    u_char	lap_port[2];
    u_char	lap_state;
    u_char	lap_reserved[3];
} lacp_actor_partner_tlv, *lacp_actor_partner_tlv_ref;

/*
 * LACP Collector TLV
 */
typedef struct lacp_collector_tlv_s {
    u_char	lac_tlv_type;		/* 0x03 */
    u_char	lac_length;		/* 16 */
    u_char	lac_max_delay[2];
    u_char	lac_reserved[12];
} lacp_collector_tlv, *lacp_collector_tlv_ref;


/* 
 * LACP Actor/Partner State bits
 */
#define LACP_ACTOR_PARTNER_STATE_LACP_ACTIVITY		0x01
#define LACP_ACTOR_PARTNER_STATE_LACP_TIMEOUT		0x02
#define LACP_ACTOR_PARTNER_STATE_AGGREGATION		0x04
#define LACP_ACTOR_PARTNER_STATE_SYNCHRONIZATION	0x08
#define LACP_ACTOR_PARTNER_STATE_COLLECTING		0x10
#define LACP_ACTOR_PARTNER_STATE_DISTRIBUTING		0x20
#define LACP_ACTOR_PARTNER_STATE_DEFAULTED		0x40
#define LACP_ACTOR_PARTNER_STATE_EXPIRED		0x80

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_active_lacp(lacp_actor_partner_state state)
{
    return (state | LACP_ACTOR_PARTNER_STATE_LACP_ACTIVITY);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_passive_lacp(lacp_actor_partner_state state)
{
    return (state &= ~LACP_ACTOR_PARTNER_STATE_LACP_ACTIVITY);
}

static __inline__ int
lacp_actor_partner_state_active_lacp(lacp_actor_partner_state state)
{
    return ((state & LACP_ACTOR_PARTNER_STATE_LACP_ACTIVITY) != 0);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_short_timeout(lacp_actor_partner_state state)
{
    return (state | LACP_ACTOR_PARTNER_STATE_LACP_TIMEOUT);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_long_timeout(lacp_actor_partner_state state)
{
    return (state &= ~LACP_ACTOR_PARTNER_STATE_LACP_TIMEOUT);
}

static __inline__ int
lacp_actor_partner_state_short_timeout(lacp_actor_partner_state state)
{
    return ((state & LACP_ACTOR_PARTNER_STATE_LACP_TIMEOUT) != 0);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_aggregatable(lacp_actor_partner_state state)
{
    return (state | LACP_ACTOR_PARTNER_STATE_AGGREGATION);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_individual(lacp_actor_partner_state state)
{
    return (state &= ~LACP_ACTOR_PARTNER_STATE_AGGREGATION);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_aggregatable(lacp_actor_partner_state state)
{
    return ((state & LACP_ACTOR_PARTNER_STATE_AGGREGATION) != 0);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_in_sync(lacp_actor_partner_state state)
{
    return (state | LACP_ACTOR_PARTNER_STATE_SYNCHRONIZATION);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_out_of_sync(lacp_actor_partner_state state)
{
    return (state &= ~LACP_ACTOR_PARTNER_STATE_SYNCHRONIZATION);
}

static __inline__ int
lacp_actor_partner_state_in_sync(lacp_actor_partner_state state)
{
    return ((state & LACP_ACTOR_PARTNER_STATE_SYNCHRONIZATION) != 0);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_collecting(lacp_actor_partner_state state)
{
    return (state | LACP_ACTOR_PARTNER_STATE_COLLECTING);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_not_collecting(lacp_actor_partner_state state)
{
    return (state &= ~LACP_ACTOR_PARTNER_STATE_COLLECTING);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_collecting(lacp_actor_partner_state state)
{
    return ((state & LACP_ACTOR_PARTNER_STATE_COLLECTING) != 0);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_distributing(lacp_actor_partner_state state)
{
    return (state | LACP_ACTOR_PARTNER_STATE_DISTRIBUTING);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_not_distributing(lacp_actor_partner_state state)
{
    return (state &= ~LACP_ACTOR_PARTNER_STATE_DISTRIBUTING);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_distributing(lacp_actor_partner_state state)
{
    return ((state & LACP_ACTOR_PARTNER_STATE_DISTRIBUTING) != 0);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_defaulted(lacp_actor_partner_state state)
{
    return (state | LACP_ACTOR_PARTNER_STATE_DEFAULTED);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_not_defaulted(lacp_actor_partner_state state)
{
    return (state &= ~LACP_ACTOR_PARTNER_STATE_DEFAULTED);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_defaulted(lacp_actor_partner_state state)
{
    return ((state & LACP_ACTOR_PARTNER_STATE_DEFAULTED) != 0);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_expired(lacp_actor_partner_state state)
{
    return (state | LACP_ACTOR_PARTNER_STATE_EXPIRED);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_set_not_expired(lacp_actor_partner_state state)
{
    return (state &= ~LACP_ACTOR_PARTNER_STATE_EXPIRED);
}

static __inline__ lacp_actor_partner_state
lacp_actor_partner_state_expired(lacp_actor_partner_state state)
{
    return ((state & LACP_ACTOR_PARTNER_STATE_EXPIRED) != 0);
}


/*
 * LACP Actor/Partner TLV access functions
 */
static __inline__ void
lacp_actor_partner_tlv_set_system_priority(lacp_actor_partner_tlv_ref tlv, 
					   lacp_system_priority system_priority)
{
    *((lacp_system_priority *)tlv->lap_system_priority) 
	= (lacp_system_priority)htons(system_priority);
    return;
}

static __inline__ lacp_system_priority
lacp_actor_partner_tlv_get_system_priority(const lacp_actor_partner_tlv_ref tlv)
{
    return ((lacp_system_priority)
	    ntohs(*((u_short *)tlv->lap_system_priority)));
}

static __inline__ void
lacp_actor_partner_tlv_set_key(lacp_actor_partner_tlv_ref tlv, lacp_key key)
{
    *((lacp_key *)tlv->lap_key) = (lacp_key)htons(key);
    return;
}

static __inline__ lacp_key
lacp_actor_partner_tlv_get_key(const lacp_actor_partner_tlv_ref tlv)
{
    return ((lacp_key)ntohs(*((u_short *)tlv->lap_key)));
}

static __inline__ void
lacp_actor_partner_tlv_set_port_priority(lacp_actor_partner_tlv_ref tlv, 
					 lacp_port_priority port_priority)
{
    *((lacp_port_priority *)tlv->lap_port_priority) 
	= (lacp_port_priority)htons(port_priority);
    return;
}

static __inline__ lacp_port_priority
lacp_actor_partner_tlv_get_port_priority(const lacp_actor_partner_tlv_ref tlv)
{
    return ((lacp_port_priority)ntohs(*((u_short *)tlv->lap_port_priority)));
}

static __inline__ void
lacp_actor_partner_tlv_set_port(lacp_actor_partner_tlv_ref tlv, lacp_port port)
{
    *((lacp_port *)tlv->lap_port) = (lacp_port)htons(port);
    return;
}

static __inline__ lacp_port
lacp_actor_partner_tlv_get_port(const lacp_actor_partner_tlv_ref tlv)
{
    return ((lacp_port)ntohs(*((u_short *)tlv->lap_port)));
}

/*
 * LACP Collector TLV access functions
 */
static __inline__ void
lacp_collector_tlv_set_max_delay(lacp_collector_tlv_ref tlv, 
				 lacp_collector_max_delay delay)
{
    *((lacp_collector_max_delay *)tlv->lac_max_delay) 
	= (lacp_collector_max_delay)htons(delay);
    return;
}

static __inline__ lacp_collector_max_delay
lacp_collector_tlv_get_max_delay(const lacp_collector_tlv_ref tlv)
{
    return ((lacp_collector_max_delay)ntohs(*((u_short *)tlv->lac_max_delay)));
}

typedef struct lacpdu_s {
    u_char		la_subtype;
    u_char		la_version;
    u_char		la_actor_tlv[LACPDU_ACTOR_TLV_LENGTH];
    u_char		la_partner_tlv[LACPDU_PARTNER_TLV_LENGTH];
    u_char		la_collector_tlv[LACPDU_COLLECTOR_TLV_LENGTH];
    u_char		la_terminator_type;
    u_char		la_terminator_length;
    u_char		la_reserved[50];
} lacpdu, *lacpdu_ref;

/* timer values in seconds */
#define LACP_FAST_PERIODIC_TIME		1 
#define LACP_SLOW_PERIODIC_TIME		30
#define LACP_SHORT_TIMEOUT_TIME		3
#define LACP_LONG_TIMEOUT_TIME		90
#define LACP_CHURN_DETECTION_TIME	60
#define LACP_AGGREGATE_WAIT_TIME	2

/* packet rate per second */
#define LACP_PACKET_RATE		3

/**
 ** Link Aggregation Marker Protocol definitions
 **/
#define LA_MARKER_PDU_VERSION_1			1
#define LA_MARKER_TLV_TYPE_TERMINATOR		0x00
#define LA_MARKER_TLV_TYPE_MARKER		0x01
#define LA_MARKER_TLV_TYPE_MARKER_RESPONSE	0x02

#define LA_MARKER_TLV_LENGTH			16
#define LA_MARKER_RESPONSE_TLV_LENGTH		16

typedef u_int32_t la_marker_transaction_id;

typedef struct la_marker_pdu_s {
    u_char		lm_subtype;		/* 0x02 */
    u_char		lm_version;		/* 0x01 */
    u_char		lm_marker_tlv_type;	/* 0x01 or 0x02 */
    u_char		lm_marker_tlv_length;	/* 16 */
    u_char		lm_requestor_port[2];
    u_char		lm_requestor_system[6];
    u_char		lm_requestor_transaction_id[4];
    u_char		lm_pad[2];
    u_char		lm_terminator_type;	/* 0x00 */
    u_char		lm_terminator_length;	/* 0 */
    u_char		lm_reserved[90];
} la_marker_pdu, *la_marker_pdu_ref, 
    la_marker_response_pdu, * la_marker_response_pdu_ref;

static __inline__ void
la_marker_pdu_set_requestor_port(la_marker_pdu_ref lmpdu, lacp_port port)
{
    *((lacp_port *)lmpdu->lm_requestor_port) = (lacp_port)htons(port);
    return;
}

static __inline__ lacp_port
la_marker_pdu_get_requestor_port(la_marker_pdu_ref lmpdu)
{
    return ((lacp_port)ntohs(*((lacp_port *)lmpdu->lm_requestor_port)));
}

static __inline__ void
la_marker_pdu_set_requestor_transaction_id(la_marker_pdu_ref lmpdu, 
					   la_marker_transaction_id xid)
{
    *((la_marker_transaction_id *)lmpdu->lm_requestor_transaction_id) 
	= (la_marker_transaction_id)htonl(xid);
    return;
}

static __inline__ la_marker_transaction_id
la_marker_pdu_get_requestor_transaction_id(la_marker_pdu_ref lmpdu)
{
    la_marker_transaction_id *	xid_p;

    xid_p = (la_marker_transaction_id *)lmpdu->lm_requestor_transaction_id;
    return ((la_marker_transaction_id)ntohl(*xid_p));
}

static __inline__ void
la_marker_pdu_set_requestor_system(la_marker_pdu_ref lmpdu, lacp_system sys)
{
    *((lacp_system_ref)lmpdu->lm_requestor_system) = sys;
    return;
}

static __inline__ lacp_system
la_marker_pdu_get_requestor_system(la_marker_pdu_ref lmpdu)
{
    return (*(lacp_system_ref)(lmpdu->lm_requestor_system));
}

#endif /* _NET_LACP_H_ */
