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
 *	Copyright (c) 1988, 1989, 1997, 1998 Apple Computer, Inc. 
 *
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 */

#include <string.h>

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

#include <net/if.h>
#include <net/if_types.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/ddp.h>
#include <netat/nbp.h>
#include <netat/zip.h>
#include <netat/rtmp.h>
#include <netat/routing_tables.h>	/* router */
#include <netat/at_snmp.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>

/* reaching for DDP and NBP headers in the datagram */
#define DATA_DDP(mp)	((at_ddp_t *)(gbuf_rptr(mp)))
#define	DATA_NBP(mp)	((at_nbp_t *)((DATA_DDP(mp))->data))

/* Get to the nve_entry_t part ofthe buffer */
#define	NVE_ENTRY(mp)	(nve_entry_t *)(gbuf_rptr(mp))

#ifndef	MIN
#define	MIN(a,b)	((a)>(b)?(b):(a))
#endif

#define	errno	nbperrno

	/* externs */
extern at_ifaddr_t *ifID_table[];
extern at_ifaddr_t *ifID_home;

TAILQ_HEAD(name_registry, _nve_) name_registry;

atlock_t 	nve_lock;

/* statics */
static	int		errno;
static  gbuf_t  *lzones=0;	/* head of local zones list */
static int	lzonecnt=0;		/* # zones stored in lzones	*/
static u_int  hzonehash=0;	/* hash val of home zone */
static int	nve_lock_pri;

static int	nbp_lkup_reply(nbp_req_t *, nve_entry_t *);
static int	nbp_strcmp(at_nvestr_t *, at_nvestr_t *, u_char);
static int	nbp_setup_resp(nbp_req_t *, int);
static int	nbp_send_resp(nbp_req_t *);
static int	nbp_validate_n_hash(nbp_req_t *, int, int);
static	nve_entry_t	*nbp_search_nve();
static int isZoneLocal(at_nvestr_t *);

/* macros */
#define NVE_LOCK nve_lock

/* prototypes */
void nbp_delete_entry();
extern int at_reg_mcast();
extern at_nvestr_t *getRTRLocalZone(zone_usage_t *);
extern void	nbp_add_multicast( at_nvestr_t *, at_ifaddr_t *);

static long nbp_id_count = 0;

void sethzonehash(elapp)
     at_ifaddr_t *elapp;
{
	if (elapp->startup_zone.len)  {
		hzonehash = nbp_strhash(&elapp->startup_zone);
	}
}

void nbp_shutdown()
{
	/* delete all NVE's and release buffers */
	register nve_entry_t	*nve_entry, *nve_next;

	ATDISABLE(nve_lock_pri,NVE_LOCK);
        for ((nve_entry = TAILQ_FIRST(&name_registry)); nve_entry; nve_entry = nve_next) {
                nve_next = TAILQ_NEXT(nve_entry, nve_link);

                /* NB: nbp_delete_entry calls TAILQ_REMOVE */
		nbp_delete_entry(nve_entry);
	}
	ATENABLE(nve_lock_pri,NVE_LOCK);

	if (lzones) {
		gbuf_freem(lzones);
		lzonecnt = 0;
		lzones = NULL; 
	}
} /* nbp_shutdown */

static
u_char *nbp2zone(nbp, maxp)
	at_nbp_t *nbp;
	u_char *maxp;
{

	u_char *p;

	p = (u_char*)&nbp->tuple[0].enu_entity;	/* p -> object */
	if (p >= maxp) return NULL;
	p += (*p +1);				/* p -> type   */
	if (p >= maxp) return NULL;
	p += (*p +1);				/* p -> zone   */
	if (p >= maxp) return NULL;
	if ((p + *p) >= maxp) return NULL;
	return(p);
}

void nbp_input(m, ifID)
     register gbuf_t	*m;
     register at_ifaddr_t *ifID;

{
	register at_ddp_t 	*ddp = DATA_DDP(m);
	register at_nbp_t	*nbp = DATA_NBP(m);
	register nve_entry_t	*nve_entry, *next_nve;
	register RT_entry	*rt;
	register int ddpSent = FALSE; 	/* true if we re-sent this pkt (don't free) */
	struct etalk_addr mcastAddr;
	nbp_req_t	nbp_req;
	u_char *p;
	
	/* from original nbp_input() when this function was nbp_handler() */
	if ((gbuf_type(m) != MT_DATA && gbuf_type(m) != MSG_DATA) ||
	    ddp->type != DDP_NBP) {
		gbuf_freem(m);	    
		return;
	}

	/* Some initializations */
	nbp_req.response = NULL;
	nbp_req.request = m;
	nbp_req.space_unused = nbp_req.flags = 0;

	dPrintf(D_M_NBP_LOW, D_L_USR1,
		("nbp_input control:%d tuplecount:%d id:%d\n",
		nbp->control, nbp->tuple_count, nbp->at_nbp_id));
	switch (nbp->control) {
	case NBP_LKUP :
	  {
		at_net_al dst_net;

		dst_net = NET_VALUE(ddp->dst_net);
		dPrintf(D_M_NBP_LOW, D_L_USR2, (" LKUP %s\n",
			ifID != ifID_home ? "non-home" : "home"));
		if ( ROUTING_MODE && (NET_VALUE(ddp->dst_net) != 0)
			&& ((dst_net < ifID->ifThisCableStart)
			    || (dst_net > ifID->ifThisCableEnd)) ) {
			routing_needed(m, ifID, TRUE);
			ddpSent = TRUE;
			break;
		}
	  }

		if (nbp_validate_n_hash (&nbp_req, TRUE, FALSE) == 0) {
			nbp_req.func = nbp_lkup_reply;
			(void) nbp_search_nve(&nbp_req, ifID);
			if (nbp_req.response) {
				nbp_send_resp(&nbp_req);
			}
		}
#ifdef NBP_DEBUG
	{
		char zone[35],object[35],type[35];
		strncpy(zone,nbp_req.nve.zone.str, nbp_req.nve.zone.len);
		strncpy(object,nbp_req.nve.object.str, nbp_req.nve.object.len);
		strncpy(type,nbp_req.nve.type.str, nbp_req.nve.type.len);
		object[nbp_req.nve.object.len] = '\0';
		zone[nbp_req.nve.zone.len] = '\0';
		type[nbp_req.nve.type.len] = '\0';
		if (ifID != ifID_home) 
			dPrintf(D_M_NBP_LOW,D_L_USR2,
				("nbp_LKUP for:%s:%s@%s", object, type, zone));
	}
#endif /* NBP_DEBUG */

		break;
	case NBP_FWDRQ: 
		{
 		register int	zhome=0;
				/* true if home zone == destination zone */
 		register int	zno, i;
 		register  gbuf_t	*m2;
		register error_found =0;
		register at_ifaddr_t *ifIDorig;

		if (!ROUTING_MODE)	/* for routers only! */
			break;

		ifIDorig = ifID;
		ifID= NULL;
		for (i = 0 ; i < RT_maxentry; i++) {
			rt = &RT_table[i];
			if ((rt->EntryState & RTE_STATE_PERMANENT) &&
				NET_VALUE(ddp->dst_net) >= rt->NetStart && 
				NET_VALUE(ddp->dst_net) <=	rt->NetStop
			   ) {
			   	/* sanity check */
			   	if (rt->NetPort >= IF_TOTAL_MAX) {
					dPrintf(D_M_NBP,D_L_ERROR,
						("nbp_input:FWDREQ: bad port# from RT_table\n"));
					error_found = TRUE;
					break;
				}
			 	ifID = ifID_table[rt->NetPort];
				if (!ifID) {
					dPrintf(D_M_NBP,D_L_ERROR,
						("nbp_input:FWDREQ: ifID %s\n", 
						!ifID ? "not found" : "invalid"));
					error_found = TRUE;
					break;
				}
				if (ifID->ifState == LAP_OFFLINE) {
					dPrintf(D_M_NBP,D_L_ERROR,
						("nbp_input:FWDREQ: ifID offline (port %d)\n",
					  	rt->NetPort));
					error_found = TRUE;
					break;
				}
			   break;
			}
		}
		if (error_found) /* the port is not correct */
			break;

		if (!ifID) { /* this packet is not for us, let the routing engine handle it  */
			routing_needed(m, ifIDorig, TRUE);
			ddpSent= TRUE;
			break;
		}

		/* 
		 * At this point, we have a valid Forward request for one of our 
		 * directly connected port. Convert it to a NBP Lookup
		 */

		nbp->control = NBP_LKUP;
	 	NET_ASSIGN(ddp->dst_net, 0);
	 	ddp->dst_node = 255;


 /*### LD 01/18/94 Check if the dest is also the home zone. */
 
 		p = nbp2zone(nbp, gbuf_wptr(m));
 		if ((p == NULL) || !(zno = zt_find_zname(p))) {
 			dPrintf(D_M_NBP,D_L_WARNING,
 				("nbp_input: FWDRQ:zone not found\n"));
			break;
 		}
		if (isZoneLocal((at_nvestr_t*)p)) 
			zhome = TRUE;				/* one of our  ports is in destination zone */
		if (!zt_get_zmcast(ifID, p, &mcastAddr)) {
			dPrintf(D_M_NBP,D_L_ERROR,
				("nbp_input: FDWREQ:zt_get_zmcast error\n"));
			break;
		}
			

 		if (zhome) { /*### LD 01/18/95  In case our home is here, call back nbp */
 
 			if (!(m2 = (gbuf_t *)gbuf_copym((gbuf_t *)m))) {
 				dPrintf(D_M_NBP,D_L_ERROR, 
 					("nbp_input: FWDRQ:gbuf_copym failed\n"));
 				break;
 			}
 
 			ddp = DATA_DDP(m2);
 			nbp = DATA_NBP(m2);
 			nbp->control  = NBP_LKUP;
 	 		NET_ASSIGN(ddp->dst_net, 0);
 	 		ddp->dst_node = 255;
 			dPrintf(D_M_NBP,D_L_INFO, 
 				("nbp_input: FWDRQ:loop back for us\n"));
 			nbp_input(m2, ifID_home);
 		}
 
		if (FDDI_OR_TOKENRING(ifID->aa_ifp->if_type))
			ddp_bit_reverse(&mcastAddr);
		ddp_router_output(m, ifID, ET_ADDR,NULL,NULL, &mcastAddr);
		ddpSent = TRUE;
		}
		break;

	case NBP_BRRQ:
		{
		register int	zno;		/* zone table entry numb */
		register int 	ztind;		/* zone bitmap index into RT_entry */
		register int	ztbit;		/* zone bit to check within above index */
		register int	zhome=0;	/* true if home zone == destination zone */
		register int	i;
		register  gbuf_t	*m2, *m3;
		register int fromUs = FALSE;
		register at_socket ourSkt;	/* originating skt */

		/* for router & MH local only */
		if ((!(MULTIHOME_MODE && FROM_US(ddp))) && !ROUTING_MODE) {
			dPrintf(D_M_NBP,D_L_USR2,
				("nbp_input: BRREQ:non router or MH local\n"));

			break;
		}
 		p = nbp2zone(nbp, gbuf_wptr(m));
		if ((p == NULL) || !(zno = zt_find_zname(p))) {
			break;
		}
		if (MULTIHOME_MODE && ifID->ifRouterState == NO_ROUTER) {
			((at_nvestr_t*)p)->len = 1;
			((at_nvestr_t*)p)->str[0] = '*';
		}
		if (isZoneLocal((at_nvestr_t*)p)) {
			zhome = TRUE;		/* one of our ports is in destination zone */
		}
		if (FROM_US(ddp)){	/* save, before we munge it */
			fromUs = TRUE;
			ourSkt = ddp->src_socket;
			dPrintf(D_M_NBP,D_L_USR2,
				("nbp_input:BRRQ from us net:%d\n",
				(int)NET_VALUE(ddp->src_net)));
		}
			/* from ZT_CLR_ZMAP */
		i = zno - 1;
		ztind = i >> 3;
		ztbit = 0x80 >> (i % 8);
		for (i=0,rt=RT_table; i<RT_maxentry; i++,rt++) {
			if (!(rt->ZoneBitMap[ztind] & ztbit)) 		/* if zone not in route, skip*/
				continue;
/*		dPrintf(D_M_NBP, D_L_USR3,
			("nbp_input: BRREQ: port:%d, entry %d\n",
				rt->NetPort, i));
*/

			ifID = ifID_table[rt->NetPort];
			if (!ifID) {
				dPrintf(D_M_NBP, D_L_ERROR, 
					("nbp_input:BRRQ: ifID %s\n", 
					!ifID ? "not found" : "invalid"));
				break;
			}

			ddp = DATA_DDP(m);
			ddp->src_node = ifID->ifThisNode.s_node;
			NET_ASSIGN(ddp->src_net,  ifID->ifThisNode.s_net);
			ddp->src_socket = NBP_SOCKET;
			if (!(m2 = (gbuf_t *)gbuf_copym((gbuf_t *)m))) {
				dPrintf(D_M_NBP,D_L_ERROR, 
					("nbp_input: BRREQ:gbuf_copym failed\n"));
				break;
			}

			ddp = DATA_DDP(m2);
			nbp = DATA_NBP(m2);
/*			nbp->tuple[0].enu_addr.socket = NBP_SOCKET; */
			if (MULTIHOME_MODE && fromUs ) {
				/* set the return address of the lookup to that of the
				   interface it's going out on so that replies come back
				   on that net */
				dPrintf(D_M_NBP,D_L_USR3, 
				   ("nbp_input: BRREQ: src changed to %d.%d.%d\n",
					ifID->ifThisNode.s_net,
					ifID->ifThisNode.s_node, ourSkt));
				nbp->tuple[0].enu_addr.net = ifID->ifThisNode.s_net;
				nbp->tuple[0].enu_addr.node = ifID->ifThisNode.s_node;
				nbp->tuple[0].enu_addr.socket = ourSkt; 
				ddp->src_socket = NBP_SOCKET;
			}
			else
				dPrintf(D_M_NBP, D_L_USR3, 
					("nbp_input: BRREQ: not from us\n"));

			dPrintf(D_M_NBP, D_L_USR3,
				("nbp_input dist:%d\n", rt->NetDist));
			if (rt->NetDist == 0) {			/* if direct connect, *we* do the LKUP */
				nbp->control  = NBP_LKUP;
	 			NET_ASSIGN(ddp->dst_net, 0);
	 			ddp->dst_node = 255;
				if (!zt_get_zmcast(ifID, p, &mcastAddr)) {
					dPrintf(D_M_NBP,D_L_ERROR, 
						("nbp_input: BRRQ:zt_get_zmcast error\n"));
					break;
				}
				if (FDDI_OR_TOKENRING(ifID->aa_ifp->if_type))
					ddp_bit_reverse(&mcastAddr);
				ddp_router_output(m2, ifID, ET_ADDR, NULL, NULL, &mcastAddr); 
			}
			else {							/* else fwd to router */
				ddp->dst_node = 0;
				if (rt->NetStart == 0)		/* if Ltalk */
					NET_ASSIGN(ddp->dst_net, rt->NetStop);
				else	
					NET_ASSIGN(ddp->dst_net, rt->NetStart);
				nbp->control  = NBP_FWDRQ;
				ddp_router_output(m2, ifID, AT_ADDR, 
						  rt->NextIRNet, rt->NextIRNode, 
						  NULL); 
			}
		}
		if (!zhome)
			break;

		if (!(m3 = (gbuf_t *)gbuf_copym((gbuf_t *)m))) {
			dPrintf(D_M_NBP,D_L_ERROR, 
				("nbp_input: BRREQ:gbuf_copym failed\n"));
			break;
		}

		ddp = DATA_DDP(m3);
		nbp = DATA_NBP(m3);
				
		nbp->control  = NBP_LKUP;
	 	NET_ASSIGN(ddp->dst_net, 0);
	 	ddp->dst_node = 255;
 		dPrintf(D_M_NBP,D_L_INFO, ("nbp_input: BRRQ:loop back for us\n"));
		nbp_input(m3, ifID_home);
		break;
		}

	case NBP_LKUP_REPLY:
		
		if (!ROUTING_MODE)	/* for routers only! */
			break;

		dPrintf(D_M_NBP,D_L_WARNING, 
			("nbp_input: routing needed for LKUP_REPLY: from %d.%d\n",
			 NET_VALUE(ddp->src_net), ddp->src_node));
		routing_needed(m, ifID, TRUE);
		ddpSent = TRUE;
		break;
		
	default :
		dPrintf(D_M_NBP,D_L_ERROR, 
			("nbp_input: unhandled pkt: type:%d\n", nbp->control));

		routing_needed(m, ifID, TRUE);
		ddpSent = TRUE;
		break;
	} /* switch control */

	if (!ddpSent)
		gbuf_freem(m);
	return;
} /* nbp_input */

static	int	nbp_validate_n_hash (nbp_req, wild_ok, checkLocal)
     register nbp_req_t	*nbp_req;
     register int	wild_ok;
     register int	checkLocal;	/* if true check if local zone */
{
        register at_nvestr_t	*object, *type, *zone;
	at_nbptuple_t	*tuple;
	register int	i, part_wild;

	tuple = DATA_NBP(nbp_req->request)->tuple;
	nbp_req->flags = 0;
#ifdef COMMENTED_OUT
	{
		int net,node,skt;
		net = tuple->enu_addr.net;
		node = tuple->enu_addr.node;
		skt = tuple->enu_addr.socket;
		dPrintf(D_M_NBP_LOW,D_L_USR4,
			("nbp_validate: tuple addr:%d:%d:%d\n",net,node,skt));
	}
#endif /* COMMENTED_OUT */

	/* tuple is in the compressed (no "filler") format */
	object = (at_nvestr_t *)&tuple->enu_entity;
	type = (at_nvestr_t *)(&object->str[object->len]);
	zone = (at_nvestr_t *)(&type->str[type->len]);
	
	if (object->len > NBP_NVE_STR_SIZE || type->len > NBP_NVE_STR_SIZE || 
		zone->len > NBP_NVE_STR_SIZE) {
		dPrintf(D_M_NBP_LOW, D_L_WARNING, 
			("nbp_val_n_hash: bad str len\n"));
		errno = EINVAL;
		return (-1);
	}
	
#ifdef NBP_DEBUG
	{
		char xzone[35],xobject[35],xtype[35];
		strncpy(xzone,zone->str, zone->len);
		strncpy(xobject,object->str, object->len);
		strncpy(xtype,type->str, type->len);
		xobject[object->len] = '\0';
		xzone[zone->len] = '\0';
		xtype[type->len] = '\0';
		dPrintf(D_M_NBP_LOW, D_L_USR4,
			("nbp_validate: looking for %s:%s@%s\n",
			xobject, xtype, xzone));
	}
#endif /* NBP_DEBUG */
	/* Is this request for our zone ?? */
	nbp_req->nve.zone.len = zone->len;
	nbp_req->nve.zone_hash = 0;
	bcopy(zone->str,nbp_req->nve.zone.str, zone->len);

	if (checkLocal && !isZoneLocal(zone)) {
		char str[35];
		strncpy(str,zone->str,zone->len);
		str[zone->len] = '\0';
		dPrintf(D_M_NBP_LOW,D_L_WARNING,
			("nbp_val_n_hash bad zone: %s\n", str));
		errno = EINVAL;
		return(-1);
	}

	if (!DEFAULT_ZONE(zone)) {
		nbp_req->nve.zone_hash = nbp_strhash(& nbp_req->nve.zone);
	}

	nbp_req->nve.address = tuple->enu_addr;
	nbp_req->nve.object.len = object->len;
	nbp_req->nve.object_hash = 0;
	if (object->len == 1 && (object->str[0] == NBP_ORD_WILDCARD ||
		object->str[0] == NBP_SPL_WILDCARD)) {
		if (wild_ok)
			nbp_req->flags |= NBP_WILD_OBJECT;
		else {
			dPrintf(D_M_NBP_LOW, D_L_WARNING, 
				("nbp_val_n_hash: wild not okay\n"));
			errno = EINVAL;
			return (-1);
		}
	} else{
		for (i = part_wild = 0; (unsigned) i<object->len; i++) {
			if (object->str[i] == NBP_SPL_WILDCARD)
				if (wild_ok)
					if (part_wild) {
					  dPrintf(D_M_NBP_LOW, D_L_WARNING, 
						  ("nbp_val_n_hash: too many parts wild\n"));
					  errno = EINVAL;
					  return (-1);
					} else
					  part_wild++;
				else {
				  dPrintf(D_M_NBP_LOW, D_L_WARNING, 
					  ("nbp_val_n_hash: wild not okay2\n"));
				  errno = EINVAL;
				  return (-1);
				}
			nbp_req->nve.object.str[i] = object->str[i];
		}
		if (!part_wild)
			nbp_req->nve.object_hash = 
				nbp_strhash(&nbp_req->nve.object);
	}

	nbp_req->nve.type.len = type->len;
	nbp_req->nve.type_hash = 0;
	if (type->len == 1 && (type->str[0] == NBP_ORD_WILDCARD ||
		type->str[0] == NBP_SPL_WILDCARD)) {
		if (wild_ok)
			nbp_req->flags |= NBP_WILD_TYPE;
		else {
			dPrintf(D_M_NBP_LOW, D_L_WARNING, 
				("nbp_val_n_hash: wild not okay3\n"));
			errno = EINVAL;
			return (-1);
		}
	} else {
		for (i = part_wild = 0; (unsigned) i<type->len; i++) {
			if (type->str[i] == NBP_SPL_WILDCARD)
				if (wild_ok)
					if (part_wild) {
					  dPrintf(D_M_NBP_LOW, D_L_WARNING, 
						  ("nbp_val_n_hash: too many parts wild2\n"));
					  errno = EINVAL;
					  return (-1);
					} else
					  part_wild++;
				else {
					errno = EINVAL;
					return (-1);
				}
			nbp_req->nve.type.str[i] = type->str[i];
		}
		if (!part_wild)
			nbp_req->nve.type_hash = 
				nbp_strhash(&nbp_req->nve.type);
	}
#ifdef NBP_DEBUG
	{
		char zone[35],object[35],type[35];
		strncpy(zone,nbp_req->nve.zone.str, nbp_req->nve.zone.len);
		strncpy(object,nbp_req->nve.object.str, nbp_req->nve.object.len);
		strncpy(type,nbp_req->nve.type.str, nbp_req->nve.type.len);
		object[nbp_req->nve.object.len] = '\0';
		zone[nbp_req->nve.zone.len] = '\0';
		type[nbp_req->nve.type.len] = '\0';
		dPrintf(D_M_NBP_LOW,D_L_USR4,
			("nbp_validate: after hash: %s:%s@%s\n",
			object, type, zone));
	}
#endif /* NBP_DEBUG */
	return(0);
} /* nbp_validate_n_hash */


/* Upshifts in place */
static	void	nbp_upshift (str, count)
register u_char	*str;
register int	count;
{
	register int	i, j;
	register u_char	ch;
	static	unsigned char	lower_case[] =
		{0x8a, 0x8c, 0x8d, 0x8e, 0x96, 0x9a, 0x9f, 0xbe,
		 0xbf, 0xcf, 0x9b, 0x8b, 0x88, 0};
	static	unsigned char	upper_case[] = 
		{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0xae,
		 0xaf, 0xce, 0xcd, 0xcc, 0xcb, 0};

	for (j=0 ; j<count ; j++) {
		ch = str[j];
		if (ch >= 'a' && ch <= 'z')
			str[j] = ch + 'A' - 'a';
		else if (ch & 0x80)
			for (i=0; lower_case[i]; i++)
				if (ch == lower_case[i])
					str[j] = upper_case[i];
	}
}


u_int nbp_strhash (nvestr)
     register at_nvestr_t	*nvestr;
{
	/* upshift while hashing */
	register u_int	hash = 0;
	register int	i, len;
	union {
		u_char	h_4char[4];
		int	h_int;
	} un;

	for (i=0; (unsigned) i < nvestr->len; i+=sizeof(int)) {
		len = MIN((nvestr->len-i), sizeof(int));
		if (len == sizeof(int))
			bcopy(&(nvestr->str[i]), &un, sizeof(un));
		else {
			un.h_int = -1;
			for ( ; (unsigned) i<nvestr->len; i++)
				un.h_4char[i % sizeof(int)] = nvestr->str[i];
		}
		nbp_upshift (un.h_4char, len);
		hash ^= un.h_int;
	}
	
	return (hash);
} /* nbp_strhash */

static	nve_entry_t *nbp_search_nve (nbp_req, ifID)
     register nbp_req_t	*nbp_req;
     register at_ifaddr_t 	*ifID;		/* NULL ok */
{
	register nve_entry_t	*nve_entry;

#ifdef NBP_DEBUG
	{
		char zone[35],object[35],type[35];
		strncpy(zone,nbp_req->nve.zone.str, nbp_req->nve.zone.len);
		strncpy(object,nbp_req->nve.object.str, nbp_req->nve.object.len);
		strncpy(type,nbp_req->nve.type.str, nbp_req->nve.type.len);
		object[nbp_req->nve.object.len] = '\0';
		zone[nbp_req->nve.zone.len] = '\0';
		type[nbp_req->nve.type.len] = '\0';
		dPrintf(D_M_NBP_LOW, D_L_USR4,
				("nbp_search: looking for %s:%s@%s resp:0x%x\n",object,type,zone,
				(u_int) nbp_req->response));
	}
#endif /* NBP_DEBUG */
	ATDISABLE(nve_lock_pri,NVE_LOCK);
	TAILQ_FOREACH(nve_entry, &name_registry, nve_link) {
		if ((nbp_req->nve.zone_hash) && 
			((nbp_req->nve.zone_hash != 
			  nve_entry->zone_hash) &&
			 (nbp_req->nve.zone_hash != hzonehash)
		    )
		   ) {
			dPrintf(D_M_NBP_LOW,D_L_USR4,
				("nbp_search: no match for zone, req hash:%x\n",
			nbp_req->nve.zone_hash));
			continue;
		}
		else { 	/* for this entry's zone OR no zone in request or entry */
			/* only in singleport mode (!MULTIPORT_MODE) with 
			   empty PRAM can an entry have '*' for it's zone
			*/
			at_nvestr_t *ezone=&nve_entry->zone;
			at_nvestr_t *rzone=&nbp_req->nve.zone;
			if (!DEFAULT_ZONE(rzone) && !DEFAULT_ZONE(ezone))  {
				if (nbp_strcmp (rzone, ezone, 0) != 0)
					continue;
			}
			else {
			    if (MULTIHOME_MODE && ifID && 
				(nve_entry->address.net != 
				 ifID->ifThisNode.s_net)) {
				dPrintf(D_M_NBP, D_L_USR4, 
					("nbp search ifID (%d) & req net (%d) not eq\n",
					 nve_entry->address.net,
					 ifID->ifThisNode.s_net));
				continue;
			    }
			    if (ifID)
				dPrintf(D_M_NBP, D_L_USR4, 
					("nbp search ifID (%d) & req net (%d)  equal\n",
					 nve_entry->address.net,
					 ifID->ifThisNode.s_net));
			}
		
		}
		if (!(nbp_req->flags & NBP_WILD_OBJECT)) {
			if ((nbp_req->nve.object_hash) && 
				(nbp_req->nve.object_hash != 
				nve_entry->object_hash))
				continue;
			else {
				if (nbp_strcmp (&nbp_req->nve.object, 
					&nve_entry->object, 
					NBP_SPL_WILDCARD) != 0)
					continue;
			}
		}


		if (!(nbp_req->flags & NBP_WILD_TYPE)) {
			if ((nbp_req->nve.type_hash) && 
				(nbp_req->nve.type_hash !=nve_entry->type_hash))
				continue;
			else {
				if (nbp_strcmp (&nbp_req->nve.type, 
					&nve_entry->type, 
					NBP_SPL_WILDCARD) != 0)
					continue;
			}
		}

		/* Found a match! */
#ifdef NBP_DEBUG
	{
		char zone[35],object[35],type[35];

		strncpy(zone,nbp_req->nve.zone.str, nbp_req->nve.zone.len);
		strncpy(object,nbp_req->nve.object.str, nbp_req->nve.object.len);
		strncpy(type,nbp_req->nve.type.str, nbp_req->nve.type.len);
		object[nbp_req->nve.object.len] = '\0';
		zone[nbp_req->nve.zone.len] = '\0';
		type[nbp_req->nve.type.len] = '\0';
		dPrintf(D_M_NBP_LOW, D_L_USR2,
			("nbp_search: found  %s:%s@%s  net:%d\n",
			object, type, zone, (int)nve_entry->address.net));
	}
#endif /* NBP_DEBUG */
		if (nbp_req->func != NULL) {
			if ((*(nbp_req->func))(nbp_req, nve_entry) != 0) {
				/* errno expected to be set by func */
				ATENABLE(nve_lock_pri,NVE_LOCK);
				return (NULL);
			}
		} else {
			ATENABLE(nve_lock_pri,NVE_LOCK);
			return (nve_entry);
		}
	}
	ATENABLE(nve_lock_pri,NVE_LOCK);

	errno = 0;
	return (NULL);
} /* nbp_search_nve */

static	int	nbp_lkup_reply (nbp_req, nve_entry)
register nbp_req_t	*nbp_req;
register nve_entry_t	*nve_entry;
{
	register at_nbptuple_t	*tuple;
	register int	tuple_size, buf_len;
	register int	obj_len, type_len;
	u_char *p;

	/* size of the current tuple we want to write... */
	tuple_size = nve_entry->object.len + 1 + 	/* object */
			nve_entry->type.len + 1 + 	/* type */
			2 + 				/* zone */
			sizeof (at_inet_t) + 1;		/* addr + enum */

	buf_len = ((nbp_req->flags & NBP_WILD_MASK) ? DDP_DATA_SIZE:tuple_size);
	if (nbp_req->response == NULL) {
		if (nbp_setup_resp (nbp_req, buf_len) != 0)
			/* errno expected to be set by nbp_setup_resp() */
			return (-1);
	}

	if ((nbp_req->space_unused < tuple_size) || 
		(DATA_NBP(nbp_req->response)->tuple_count == NBP_TUPLE_MAX)) {
		if (nbp_send_resp (nbp_req) != 0)
			return (-1);
		if (nbp_setup_resp (nbp_req, buf_len) != 0)
			return (-1);
	}

	/* At this point, we have a response buffer that can accommodate the
	 * tuple we want to write. Write it!
	 */
	tuple = (at_nbptuple_t *)gbuf_wptr(nbp_req->response);
	tuple->enu_addr = nve_entry->address;
	tuple->enu_enum = nve_entry->enumerator;

        /* tuple is in the compressed (no "filler") format */
	p = (u_char *)&tuple->enu_entity.object;
	obj_len = nve_entry->object.len + 1;
	bcopy(&nve_entry->object, p, obj_len);
	p += obj_len;
	type_len = nve_entry->type.len + 1;
	bcopy(&nve_entry->type, p, type_len);
	p += type_len;
	p[0] = (u_char)1;
	p[1] = '*';
										
	nbp_req->space_unused -= tuple_size;
	gbuf_winc(nbp_req->response, tuple_size);

	/* increment the tuple count in header by 1 */
	DATA_NBP(nbp_req->response)->tuple_count++;

	return (0);
}


static	int	nbp_strcmp (str1, str2, embedded_wildcard)
register at_nvestr_t	*str1, *str2;
register u_char	embedded_wildcard;	/* If str1 may contain a character
					 * that's to be treated as an
					 * embedded wildcard, this character
					 * is it.  Making this special case
					 * since for zone names, squiggly
					 * equal is not to be treated as a 
					 * wildcard.
					 */
{
	u_char	        ch1,ch2;
	register int	i1, i2;
	register int	reverse = 0;
	register int	left_index;

	/* Embedded wildcard, if any, could only be in the first string (str1).
	 * returns 0 if two strings are equal (modulo case), -1 otherwise 
	 */
	
	if (str1->len == 0 || str2->len == 0) {
		return (-1);
	}	
	
	/* Wildcards are not allowed in str2.
	 *
	 * If str1 could potentially contain an embedded wildcard, since the
	 * embedded wildcard matches ZERO OR MORE characters, str1 can not be
	 * more than 1 character longer than str2.
	 *
	 * If str1 is not supposed to have embedded wildcards, the two strs 
	 * must be of equal length.
	 */
	if ((embedded_wildcard && (str2->len < (unsigned) (str1->len-1))) ||
		(!embedded_wildcard && (str2->len !=  str1->len))) {
		return (-1);
	}

	for (i1 = i2 = left_index = 0; (unsigned) i1 < str1->len ;) {
		ch1 = str1->str[i1];
		ch2 = str2->str[i2];

		if (embedded_wildcard && (ch1==embedded_wildcard)) {
			/* hit the embedded wild card... start comparing from 
			 * the other end of the string.
			 */
			reverse++;
			/* But, if embedded wildcard was the last character of 
			 * the string, the two strings match, so return okay.
			 */
			if (i1 == str1->len-1) {
				return (0);
			}
			
			i1 = str1->len - 1;
			i2 = str2->len - 1;
			
			continue;
		}
		
		nbp_upshift(&ch1, 1);
		nbp_upshift(&ch2, 1);

		if (ch1 != ch2) {
			return (-1);
		}
		
		if (reverse) {
			i1--; i2--;
			if (i1 == left_index) {
				return (0);
			}
		} else {
			i1++; i2++; left_index++;
		}
	}
	return (0);
}


static	void	nbp_setup_hdr (nbp_req)
register nbp_req_t	*nbp_req;
{
	register at_ddp_t	*ddp;
	register at_nbp_t	*nbp;

	ddp = DATA_DDP(nbp_req->response);
	nbp = DATA_NBP(nbp_req->response);
	
	ddp->type = DDP_NBP;
	UAS_ASSIGN(ddp->checksum, 0);
	ddp->unused = ddp->hopcount = 0;

	switch(DATA_NBP(nbp_req->request)->control) {
	case NBP_LKUP :
		ddp->dst_socket = nbp_req->nve.address.socket;
		ddp->dst_node = nbp_req->nve.address.node;
		NET_ASSIGN(ddp->dst_net, nbp_req->nve.address.net);
		nbp->control = NBP_LKUP_REPLY;
		break;
	}
	nbp->at_nbp_id = DATA_NBP(nbp_req->request)->at_nbp_id;
	return;
}


static	int	nbp_setup_resp (nbp_req, tuples_size)
register nbp_req_t	*nbp_req;
register int		tuples_size;
{
	int	buf_size = tuples_size + DDP_X_HDR_SIZE + NBP_HDR_SIZE;
	nbp_req->response = gbuf_alloc(AT_WR_OFFSET+buf_size, PRI_MED);
	if (nbp_req->response == NULL) {
		errno = ENOBUFS;
		return(-1);
	}
	gbuf_rinc(nbp_req->response, AT_WR_OFFSET);
	gbuf_wset(nbp_req->response, DDP_X_HDR_SIZE + NBP_HDR_SIZE);
	nbp_setup_hdr(nbp_req);

	DATA_NBP(nbp_req->response)->tuple_count = 0;
	nbp_req->space_unused = tuples_size;

	return (0);
} /* nbp_setup_resp */


static	int	nbp_send_resp (nbp_req)
register nbp_req_t	*nbp_req;
{
	int		status;

	status = ddp_output(&nbp_req->response, (at_socket)NBP_SOCKET, FALSE);
	nbp_req->response = NULL;
	errno = status;
	return(errno?-1:0);
}

void nbp_add_multicast(zone, ifID)
     at_nvestr_t *zone;
     at_ifaddr_t *ifID;
{
	char data[ETHERNET_ADDR_LEN];
	int i;

	if (zone->str[0] == '*')
		return;

	{
	  char str[35];
	  strncpy(str,zone->str,zone->len);
	  str[zone->len] = '\0';
	  dPrintf(D_M_NBP_LOW, D_L_USR3,
		  ("nbp_add_multi getting mc for %s\n", str));
	}
	zt_get_zmcast(ifID, zone, data); 
	if (FDDI_OR_TOKENRING(ifID->aa_ifp->if_type))
	  ddp_bit_reverse(data);
	dPrintf(D_M_NBP_LOW,D_L_USR3,
		("nbp_add_multi adding  0x%x%x port:%d ifID:0x%x if:%s\n",
		 *(unsigned*)data, (*(unsigned *)(data+2))&0x0000ffff,
		 i, (u_int) ifID, ifID->ifName));

	bcopy((caddr_t)data, (caddr_t)&ifID->ZoneMcastAddr, ETHERNET_ADDR_LEN);
	(void)at_reg_mcast(ifID, (caddr_t)&ifID->ZoneMcastAddr);
}


getNbpTableSize()

/* for SNMP, returns size in # of entries */
{
	register nve_entry_t *nve;
	register int i=0;

	ATDISABLE(nve_lock_pri,NVE_LOCK);
	for (nve = TAILQ_FIRST(&name_registry); nve; nve = TAILQ_NEXT(nve, nve_link), i++)
		i++;
	ATENABLE(nve_lock_pri,NVE_LOCK);
	return(i);
}

getNbpTable(p, s, c)
     snmpNbpEntry_t	*p;
     int 		s;		/* starting entry */
     int		c;		/* # entries to copy */

/* for SNMP, returns section of nbp table */
{
	register nve_entry_t *nve;
	register int i=0;
	static   int nextNo=0;		/* entry that *next points to */
	static	 nve_entry_t  *next = (nve_entry_t*)NULL;
	
	if (s && next && nextNo == s) {
		nve = next;
		i = nextNo;
	}
	else
		nve = TAILQ_FIRST(&name_registry);

	ATDISABLE(nve_lock_pri,NVE_LOCK);
	for ( ; nve && c ; nve = TAILQ_NEXT(nve, nve_link), p++,i++) {
		if (i>= s) {
			p->nbpe_object = nve->object;
			p->nbpe_type   = nve->type;
			c--;
		}
	}
	ATENABLE(nve_lock_pri,NVE_LOCK);
	if (nve) {
		next = nve;
		nextNo = i;
	} else {
		next = (nve_entry_t*)NULL;
		nextNo = 0;
	}
}


#define ZONES_PER_BLK		31	/* 31 fits within a 1k blk) */
#define ZONE_BLK_SIZE		ZONES_PER_BLK * sizeof(at_nvestr_t)

int setLocalZones(newzones, size)
     at_nvestr_t *newzones;
     int size;
/* updates list of zones which are local to all active ports
   missing zones are not deleted, only missing zones are added.
*/
{
	int	bytesread=0;		/* #bytes read from tuple */
	int i=0, dupe;
	gbuf_t	*m;
	at_nvestr_t		*pnve, *pnew = newzones;

	if (!lzones) {
		if(!(lzones = gbuf_alloc(ZONE_BLK_SIZE, PRI_MED)))
			return(ENOBUFS);
		gbuf_wset(lzones,0);
	}
	while (bytesread < size) {		/* for each new zone */
		{
			char str[35];
			strncpy(str,pnew->str,pnew->len);
			str[pnew->len] = '\0';
		}
		m = lzones;				
		pnve = (at_nvestr_t*)gbuf_rptr(m);
		dupe = 0;
		for (i=0; i<lzonecnt && !dupe; i++,pnve++)  {
			if (i && !(i%ZONES_PER_BLK))
				if (gbuf_cont(m)) {
					m = gbuf_cont(m);
					pnve = (at_nvestr_t*)gbuf_rptr(m);
				}
				else
					break;
			if (pnew->len != pnve->len)
				continue;
			if (pnew->len > NBP_NVE_STR_SIZE) {
				return(0);
			}
			if (!strncmp(pnew->str, pnve->str, pnew->len)) {
				dupe=1;
				continue;
			}
		}
		if (!dupe) {
			/* add new zone */
			if (lzonecnt && !(lzonecnt%ZONES_PER_BLK)) {
				if(!(gbuf_cont(m) = gbuf_alloc(ZONE_BLK_SIZE, PRI_MED)))
					return(ENOBUFS);
				gbuf_wset(gbuf_cont(m),0);
				pnve = (at_nvestr_t*)gbuf_rptr(gbuf_cont(m));
			}
			strncpy(pnve->str,pnew->str,pnew->len);
			pnve->len = pnew->len;
			lzonecnt++;
		}
		bytesread += (pnew->len+1);
		pnew = (at_nvestr_t*) (((char *)pnew) + pnew->len + 1);
	}
	/* showLocalZones1(); */
	return(0);
}

/**********
showLocalZones1()
{
	int i;
	at_nvestr_t *pnve;
	gbuf_t	*m;
	char str[35];
	
	for (i=0;  ; i++) {
		if (!(pnve = getLocalZone(i))) {
			break;
		}
		strncpy(str,pnve->str,pnve->len);
		str[pnve->len] = '\0';
	}
}

*********/

isZoneLocal(zone)
at_nvestr_t *zone;
{
	at_nvestr_t *pnve;
	int i;
	if (DEFAULT_ZONE(zone))
		return(1);
	for (i=0;  ; i++) {
		if (!(pnve = getLocalZone(i))) 
			break;
		if (!nbp_strcmp(pnve,zone,0))
			return(1);
	}
	return(0);
}
	

#define NULL_PNVESTR (at_nvestr_t *) 0

at_nvestr_t *getLocalZone(zno)
	int zno;			/* zone number in virtual list to
					   return, 0 for first zone */
/* returns pointer to a new local zone number zno,
   returns null when no zones left.
*/
{
	zone_usage_t ifz;
	ifz.zone_index = zno;
	if (MULTIPORT_MODE) 
		return(getRTRLocalZone(&ifz));
	else
		return(getSPLocalZone(zno));
}


at_nvestr_t *getSPLocalZone(zno)
	int zno;			/* zone number in virtual list to
						   return, 0 for first zone */
/* single port mode version */
{
	int curz=0;		/* current zone */
	gbuf_t *m;
	at_nvestr_t *pnve;

	if (lzones) {
		m = lzones;
		pnve = (at_nvestr_t*)gbuf_rptr(m);
	}
	else
		return(NULL_PNVESTR);
	if ( zno>=lzonecnt )
		return(NULL_PNVESTR);
	for (curz=0; curz<zno; curz++,pnve++ ) {
		if ( curz<lzonecnt ) {
			if (curz && !(curz%ZONES_PER_BLK) ) {
				if (gbuf_cont(m)) {
					m = gbuf_cont(m);
					pnve = (at_nvestr_t*)gbuf_rptr(m);
				}
				else {
					return(NULL_PNVESTR);
				}
			}
			if (pnve->len > NBP_NVE_STR_SIZE) {
				return(NULL_PNVESTR);
			}
		}
		else
			return(NULL_PNVESTR);
	}
	return(pnve);
}

/* The following functions are used in name registration and removal */

int nbp_fillin_nve(entity, nve)
     at_entity_t   	*entity;
     nve_entry_t     	*nve;
{
	register int i;

	if (entity->object.len > NBP_NVE_STR_SIZE || 
	    entity->type.len > NBP_NVE_STR_SIZE || 
	    entity->zone.len > NBP_NVE_STR_SIZE) {
		dPrintf(D_M_NBP_LOW, D_L_WARNING, 
			("nbp_fillin_nve: bad str len\n"));
		errno = EINVAL;
		return (-1);
	}
	
	nve->zone = entity->zone;
	nve->zone_hash = 0;
	if (!isZoneLocal(&entity->zone)) {
		errno = EINVAL;
		return(-1);
	}
	/* if there's no zone, '*' gets filled in when entry is created */
	if (!DEFAULT_ZONE(&entity->zone))
		nve->zone_hash = nbp_strhash(&nve->zone);

	nve->object = entity->object;
	nve->object_hash = 0;
	if (entity->object.len == 1 && 
	    (entity->object.str[0] == NBP_ORD_WILDCARD ||
	     entity->object.str[0] == NBP_SPL_WILDCARD)) {
		dPrintf(D_M_NBP_LOW, D_L_WARNING, 
			("nbp_fillin_nve: wildcard\n"));
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < entity->object.len; i++) {
		if (entity->object.str[i] == NBP_SPL_WILDCARD) {
		dPrintf(D_M_NBP_LOW, D_L_WARNING, 
			("nbp_fillin_nve: wildcard2\n"));
			errno = EINVAL;
			return (-1);
		}
	}
	nve->object_hash = nbp_strhash(&nve->object);

	nve->type = entity->type;
	nve->type_hash = 0;
	if (entity->type.len == 1 && 
	    (entity->type.str[0] == NBP_ORD_WILDCARD ||
	     entity->type.str[0] == NBP_SPL_WILDCARD)) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < entity->type.len; i++) {
		if (entity->type.str[i] == NBP_SPL_WILDCARD) {
		dPrintf(D_M_NBP_LOW, D_L_WARNING, 
			("nbp_fillin_nve: wildcard3\n"));
			errno = EINVAL;
			return (-1);
		}
	}
	nve->type_hash = nbp_strhash(&nve->type);

	return(0);
} /* nbp_fillin_nve */

nve_entry_t *nbp_find_nve(nve)
     nve_entry_t *nve;
{
	register nve_entry_t	*nve_entry;

	ATDISABLE(nve_lock_pri,NVE_LOCK);
	TAILQ_FOREACH(nve_entry, &name_registry, nve_link) {
		if (nve->zone_hash &&
		    ((nve->zone_hash != nve_entry->zone_hash) &&
		     (nve->zone_hash != hzonehash))) {
			dPrintf(D_M_NBP_LOW,D_L_USR4,
				("nbp_find_nve: no match for zone, req hash:%x\n",
				 nve->zone_hash));
			continue;
		} 

		if ((nve->object_hash) && 
		    (nve->object_hash != nve_entry->object_hash))
			continue;

		if ((nve->type_hash) && 
		    (nve->type_hash != nve_entry->type_hash))
			continue;

		/* Found a match! */
		ATENABLE(nve_lock_pri,NVE_LOCK);
		return (nve_entry);
	}
	ATENABLE(nve_lock_pri,NVE_LOCK);

	return (NULL);
} /* nbp_find_nve */

static int nbp_enum_gen (nve_entry)
     register nve_entry_t	*nve_entry;
{
	register int		new_enum = 0;
	register nve_entry_t	*ne;

	ATDISABLE(nve_lock_pri,NVE_LOCK);
re_do:
	TAILQ_FOREACH(ne, &name_registry, nve_link) {
		if ((*(int *)&ne->address == *(int *)&nve_entry->address) &&
			(ne->enumerator == new_enum)) {
			if (new_enum == 255) {
				ATENABLE(nve_lock_pri,NVE_LOCK);
				return(EADDRNOTAVAIL);
			} else {
				new_enum++;
				goto re_do;
			}
		}
	}

	ATENABLE(nve_lock_pri,NVE_LOCK);
	nve_entry->enumerator = new_enum;
	return (0);
}

int nbp_new_nve_entry(nve_entry, ifID)
     nve_entry_t *nve_entry;
     at_ifaddr_t *ifID;
{
	gbuf_t		*tag;
	nve_entry_t	*new_entry;
	at_nvestr_t 	*zone;
	int error;

	if (!(valid_at_addr((at_inet_t *)&nve_entry->address))) {
		dPrintf(D_M_NBP_LOW, D_L_WARNING, 
			("nbp_new_nve_entry: valid_at_addr\n"));
		return(EINVAL);
	}
	if ((error = nbp_enum_gen(nve_entry)))
		return(error);

	nve_entry->unique_nbp_id = ++nbp_id_count;

	/* Got an nve entry on hand.... allocate a buffer, copy the entry
	 * on to it and stick it in the registry.
	 */
	if ((tag = gbuf_alloc(sizeof(nve_entry_t), PRI_HI)) == NULL){
		return(ENOBUFS);
	}
	gbuf_wset(tag, sizeof(nve_entry_t));
	new_entry = (nve_entry_t *)gbuf_rptr(tag);
	bcopy(nve_entry, new_entry, sizeof(nve_entry_t));

	if (DEFAULT_ZONE(&nve_entry->zone)) {
	   /* put actual zone name in entry instead of "*" */
	   /* if single port mode and no zone name, then a router
	      is down, so use pram zone name hint from elap cfg */
		if (!MULTIPORT_MODE && ifID_home->ifZoneName.str[0] == '*') {
			zone = &ifID_home->startup_zone;
		} else {
			zone = &ifID_home->ifZoneName; 
		}
		new_entry->zone = *zone;
		if ( new_entry->zone.len == 0 ) {
			new_entry->zone.str[0] = '*';
			new_entry->zone.len = 1;
		}
		new_entry->zone_hash = nbp_strhash(&new_entry->zone);
	}
	new_entry->tag = tag;
	new_entry->pid =  current_proc()->p_pid;

	ATDISABLE(nve_lock_pri,NVE_LOCK);
	TAILQ_INSERT_TAIL(&name_registry, new_entry, nve_link);
	ATENABLE(nve_lock_pri,NVE_LOCK);
	at_state.flags |= AT_ST_NBP_CHANGED;

#ifdef NBP_DEBUG
	{
		char zone[35],object[35],type[35];
		strncpy(zone,new_entry->zone.str, new_entry->zone.len);
		strncpy(object,new_entry->object.str, new_entry->object.len);
		strncpy(type,new_entry->type.str, new_entry->type.len);
		object[new_entry->object.len] = '\0';
		zone[new_entry->zone.len] = '\0';
		type[new_entry->type.len] = '\0';
		dPrintf(D_M_NBP_LOW, D_L_USR4,
			("nbp_insert: adding %s:%s@%s addr:%d.%d ",
			 object, type, zone, 
			 new_entry->address.net, new_entry->address.node));
	}
#endif /* NBP_DEBUG */

	nbp_add_multicast(&new_entry->zone, ifID);
	return (0);
} /* nbp_new_nve_entry */

void nbp_delete_entry (nve_entry)
     nve_entry_t	*nve_entry;
{
	TAILQ_REMOVE(&name_registry, nve_entry, nve_link);
	gbuf_freem(nve_entry->tag);
	at_state.flags |= AT_ST_NBP_CHANGED;
}

/* Registration of an NBP entity in multihoming mode, from AIOCNBPREG
   in at.c */
int nbp_mh_reg(nbpP)
     at_nbp_reg_t *nbpP;
{
	nve_entry_t nve;
	at_ifaddr_t *ifID = 0;
	int registered = 0;
	int finished = FALSE;

	if (nbp_fillin_nve(&nbpP->name, &nve) != 0) {
		/* bad tuple... */
		dPrintf(D_M_NBP_LOW, D_L_WARNING, 
			("nbp_mh_reg: bad tuple\n"));
		return(EINVAL);
	}
	nve.address = nbpP->addr;
	nve.ddptype = nbpP->ddptype;

	if (DEFAULT_ZONE(&nbpP->name.zone)) {
	  /* multihoming mode with the default zone specified */

		/* now find the matching interfaces */
		TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
			if (nbpP->addr.net || nbpP->addr.node) {
				/* if address is specified */
				if ((nbpP->addr.net != ifID->ifThisNode.s_net ||
				     nbpP->addr.node != ifID->ifThisNode.s_node)) 
					continue;
				else
				  	/* the address was specified, and 
					   we found the matching interface */
				  	finished = TRUE;
			} else {
				/* address is not specified, so fill in
				   the address for the interface */
				nve.address.net = ifID->ifThisNode.s_net;
				nve.address.node = ifID->ifThisNode.s_node;
			}
			nve.zone = ifID->ifZoneName;
			nve.zone_hash = nbp_strhash(&nve.zone);
			if (nbp_find_nve(&nve)) 
				continue;
			if (nbp_new_nve_entry(&nve, ifID) == 0) 
				registered++;
		}
		if (registered && !nbpP->addr.net && !nbpP->addr.node) {
			nbpP->addr.net = ifID_home->ifThisNode.s_net;
			nbpP->addr.node = ifID_home->ifThisNode.s_node;
		}
	} else {
	        /* multihoming mode with a specific zone specified */
	        /* see which segments (interfaces) are seeded for this zone */
		int zno;
		char ifs_in_zone[IF_TOTAL_MAX];
		if (!(zno = zt_find_zname(&nve.zone))) {
			dPrintf(D_M_NBP_LOW, D_L_WARNING, 
				("nbp_mh_reg: didn't find zone name\n"));
			return(EINVAL);
		}
		getIfUsage(zno-1, ifs_in_zone);

		/* now find the first matching interface */
		TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
			if (!ifs_in_zone[ifID->ifPort]) 
					/* zone doesn't match */
				continue;
			else
				/* the zone matches, so unless the 
				   address is specified and doesn't 
				   match, we only need to do this once */
				finished = TRUE;

			if (nbpP->addr.net || nbpP->addr.node) {
			    /* address is specified */
			    finished = FALSE;
			    if ((nbpP->addr.net != ifID->ifThisNode.s_net ||
				 nbpP->addr.node != ifID->ifThisNode.s_node)) 
				continue;
			    else
			  	/* the address was specified, and 
				   we found the matching interface */
			  	finished = TRUE;
			} else {
				/* address is not specified, so fill in
				   the address for the interface */
				nve.address.net = ifID->ifThisNode.s_net;
				nve.address.node = ifID->ifThisNode.s_node;
			}
			if (nbp_find_nve(&nve)) 
				continue;
			if (nbp_new_nve_entry(&nve, ifID) == 0)
				registered++;
		}
		if (registered && !nbpP->addr.net && !nbpP->addr.node) {
			nbpP->addr.net = ifID->ifThisNode.s_net;
			nbpP->addr.node = ifID->ifThisNode.s_node;
		}
	}
	nbpP->unique_nbp_id = (registered > 1)? 0: nve.unique_nbp_id;

	if (registered)
		return(0);
	else
		return(EADDRNOTAVAIL);

} /* nbp_mh_reg */
