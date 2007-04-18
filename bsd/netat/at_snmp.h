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
#ifndef _NETAT_AT_SNMP_H_
#define _NETAT_AT_SNMP_H_
#include <sys/appleapiopts.h>

#ifdef __APPLE_API_OBSOLETE

#define MAX_PHYS_ADDR_SIZE	6	/* maximum physical addr size */
#define	MAX_IFS			25	/* max # interfaces */
#define	IF_NAME_SIZE		6	/* max name length of I/F name */
#define DDP_ADDR_SIZE		3
#define	ZONE_SIZE		NBP_NVE_STR_SIZE
#define	OBJECT_SIZE   		NBP_NVE_STR_SIZE
#define	TYPE_SIZE     		NBP_NVE_STR_SIZE
#define PORT_DESC_SIZE		50
#define UPDATE_IF_CHANGED	1	/* for ioctls  */
#define UPDATE_UNCONDITIONAL 2
#define SNMP_NBP_HEADER_SIZE	(sizeof(snmpNbpTable_t) - sizeof(snmpNbpEntry_t))
	
typedef struct snmpIfCfg {
	u_short		ifc_aarpSize;	/* AARP table size for this I/F */
	u_short		ifc_addrSize;	/* Mac address size in bytes */
	u_short		ifc_type;	/* port type */
	at_net_al	ifc_start;	/* net range start */
 	at_net_al	ifc_end;	/* net range end */
	struct at_addr	ifc_ddpAddr;	/* ddp address of port */
	u_short		ifc_status;	/* port status */
	u_short		ifc_netCfg;
	u_short		ifc_zoneCfg;
	at_nvestr_t	ifc_zoneName;
	u_short		ifc_index;
	char		ifc_name[IF_NAME_SIZE];	/* I/F name (e.g. ent0 */
} snmpIfCfg_t;


typedef struct snmpCfg {
	int		pad;			/* pad for UPDATE flag when ioctl issued */
	u_int	cfg_flags;			/* at_state flags */
	int		cfg_ifCnt;		/* # I/F's up */
	snmpIfCfg_t	cfg_ifCfg[MAX_IFS];
} snmpCfg_t;

typedef struct snmpAarpEnt {
	struct at_addr	ap_ddpAddr;
	u_char		ap_physAddr[MAX_PHYS_ADDR_SIZE];
}snmpAarpEnt_t;

typedef struct snmpAarp {		/* aarp info for 1 I/F */
	time_t	at_time;		/* the time() we got this table */
	int		at_ifno;	/* the (SNMP) I/F number of this table */
	int		at_maxSize;	/* allocated size of as_table in entries */
	int		at_usedSize;	/* size of at_table used portion */
	snmpAarpEnt_t	*at_table;
} snmpAarp_t;

typedef struct snmpFlags {
	int		lap_changed;	/* set when any I/F state changes */
	int		rtmpAdded;	/* set when rtmp entry ADDED */
	int		zipAdded;	/* set when zip entry ADDED */
} snmpFlags_t;

typedef struct snmpNbpEntry	{
	at_nvestr_t		nbpe_object;
	at_nvestr_t		nbpe_type;
}snmpNbpEntry_t;

typedef struct snmpNbpTable {
	int				nbpt_entries;
	at_nvestr_t		nbpt_zone;
	snmpNbpEntry_t	nbpt_table[1];
}snmpNbpTable_t;




typedef struct snmpStats {

		/* ddp group */
	u_int		dd_outReq;
	u_int		dd_outShort;
	u_int		dd_outLong;
	u_int		dd_inTotal;
	u_int		dd_fwdReq;
	u_int		dd_inLocal;
	u_int		dd_noHandler;
	u_int		dd_noRoutes;
	u_int		dd_tooShort;
	u_int		dd_tooLong;
	u_int		dd_inBcastErr;
	u_int		dd_shortErr;
	u_int		dd_hopCount;
	u_int		dd_checkSum;

		/* ATEcho group */
		
	u_int		ec_echoReq;
	u_int		ec_echoReply;
} snmpStats_t;

#define  SNMP_TYPE_OTHER		1
#define  SNMP_TYPE_LOCAL		2
#define  SNMP_TYPE_ETHER1		3
#define  SNMP_TYPE_ETHER2		4
#define  SNMP_TYPE_TOKEN		5
#define  SNMP_TYPE_IP			6	
#define  SNMP_TYPE_SERIALPPP	7
#define  SNMP_TYPE_SERIALNONSTD	8
#define  SNMP_TYPE_VIRTUAL		9
#define  SNMP_CFG_CONFIGURED	1
#define  SNMP_CFG_GARNERED		2
#define  SNMP_CFG_GUESSED		3
#define  SNMP_CFG_UNCONFIG		4

#define  SNMP_OBJ_TYPE_AARP		0x0100
#define  SNMP_OBJ_TYPE_ECHO		0x0200
#define  SNMP_OBJ_TYPE_PORT		0x0300
#define  SNMP_OBJ_TYPE_DDP		0x0400
#define  SNMP_OBJ_TYPE_RTMP		0x0500
#define  SNMP_OBJ_TYPE_ZIP 		0x0600
#define  SNMP_OBJ_TYPE_NBP 		0x0700
#define  SNMP_OBJ_TYPE_MASK		0x0f00

#define  AARPIFINDEX			2 + SNMP_OBJ_TYPE_AARP
#define  AARPNETADDRESS			3 + SNMP_OBJ_TYPE_AARP
#define  AARPPHYSADDRESS		4 + SNMP_OBJ_TYPE_AARP
#define  ATECHOREPLIES			6 + SNMP_OBJ_TYPE_AARP
#define  ATECHOREQUESTS			7 + SNMP_OBJ_TYPE_AARP
#define  ATPORTDESCR			8 + SNMP_OBJ_TYPE_PORT
#define  ATPORTIFINDEX			10 + SNMP_OBJ_TYPE_PORT
#define  ATPORTINDEX			11 + SNMP_OBJ_TYPE_PORT
#define  ATPORTNETADDRESS		12 + SNMP_OBJ_TYPE_PORT
#define  ATPORTNETCONFIG		13 + SNMP_OBJ_TYPE_PORT
#define  ATPORTNETEND			14 + SNMP_OBJ_TYPE_PORT
#define  ATPORTNETSTART			15 + SNMP_OBJ_TYPE_PORT
#define  ATPORTSTATUS			16 + SNMP_OBJ_TYPE_PORT
#define  ATPORTTYPE			 	18 + SNMP_OBJ_TYPE_PORT
#define  ATPORTZONE			 	19 + SNMP_OBJ_TYPE_PORT
#define  ATPORTZONECONFIG		20 + SNMP_OBJ_TYPE_PORT
#define  DDPBROADCASTERRORS		21 + SNMP_OBJ_TYPE_DDP
#define  DDPCHECKSUMERRORS		22 + SNMP_OBJ_TYPE_DDP
#define  DDPFORWREQUESTS		23 + SNMP_OBJ_TYPE_DDP
#define  DDPHOPCOUNTERRORS		24 + SNMP_OBJ_TYPE_DDP
#define  DDPINLOCALDATAGRAMS	25 + SNMP_OBJ_TYPE_DDP
#define  DDPINRECEIVES			26 + SNMP_OBJ_TYPE_DDP
#define  DDPNOPROTOCOLHANDLERS	27 + SNMP_OBJ_TYPE_DDP
#define  DDPOUTLONGS			28 + SNMP_OBJ_TYPE_DDP
#define  DDPOUTNOROUTES			29 + SNMP_OBJ_TYPE_DDP
#define  DDPOUTREQUESTS			30 + SNMP_OBJ_TYPE_DDP
#define  DDPOUTSHORTS			31 + SNMP_OBJ_TYPE_DDP
#define  DDPSHORTDDPERRORS		32 + SNMP_OBJ_TYPE_DDP
#define  DDPTOOLONGERRORS		33 + SNMP_OBJ_TYPE_DDP
#define  DDPTOOSHORTERRORS		34 + SNMP_OBJ_TYPE_DDP
#define  KIPBCASTADDR			35 
#define  KIPCORE			 	36
#define  KIPENTRY			 	37
#define  KIPHOPCOUNT			38
#define  KIPNETEND			 	39
#define  KIPNETSTART			40
#define  KIPNEXTHOP			 	41
#define  KIPSHARE			 	42
#define  KIPSTATE			 	43
#define  KIPTABLE			 	44
#define  KIPTYPE			 	45
#define  LLAPCOLLISIONS			46
#define  LLAPDEFERS			 	47
#define  LLAPENTRY			 	48
#define  LLAPFCSERRORS			49 
#define  LLAPIFINDEX			50 
#define  LLAPINERRORS			51 
#define  LLAPINLENGTHERRORS		52 
#define  LLAPINNOHANDLERS		53
#define  LLAPINPKTS			 	54
#define  LLAPNODATAERRORS		55
#define  LLAPOUTPKTS			56
#define  LLAPRANDOMCTSERRORS	57
#define  NBPINDEX			 	60 + SNMP_OBJ_TYPE_NBP
#define  NBPOBJECT			 	61 + SNMP_OBJ_TYPE_NBP
#define  NBPSTATE			 	62 + SNMP_OBJ_TYPE_NBP
#define  NBPTABLE			 	63 + SNMP_OBJ_TYPE_NBP
#define  NBPTYPE			 	64 + SNMP_OBJ_TYPE_NBP
#define  NBPZONE			 	65 + SNMP_OBJ_TYPE_NBP
#define  RTMPHOPS			 	67 + SNMP_OBJ_TYPE_RTMP
#define  RTMPNEXTHOP			68 + SNMP_OBJ_TYPE_RTMP
#define  RTMPPORT			 	69 + SNMP_OBJ_TYPE_RTMP
#define  RTMPRANGEEND			70 + SNMP_OBJ_TYPE_RTMP
#define  RTMPRANGESTART			71 + SNMP_OBJ_TYPE_RTMP
#define  RTMPSTATE			 	72 + SNMP_OBJ_TYPE_RTMP
#define  RTMPTYPE			 	74 + SNMP_OBJ_TYPE_RTMP
#define  ZIPZONEINDEX			77 + SNMP_OBJ_TYPE_ZIP
#define  ZIPZONENAME			78 + SNMP_OBJ_TYPE_ZIP
#define  ZIPZONENETEND			79 + SNMP_OBJ_TYPE_ZIP
#define  ZIPZONENETSTART		80 + SNMP_OBJ_TYPE_ZIP
#define  ZIPZONESTATE			81 + SNMP_OBJ_TYPE_ZIP

#define SNMP_TYPE(var,type)	 ((var & SNMP_OBJ_TYPE_MASK) == type)	

#endif /* __APPLE_API_OBSOLETE */
#endif /* _NETAT_AT_SNMP_H_ */
