/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 *	Copyright (c) 1988, 1989, 1993-1998 Apple Computer, Inc. 
 */

/* at_elap.c: 2.0, 1.29; 10/4/93; Apple Computer, Inc. */

/* This is the file which implements all the streams driver 
 * functionality required for EtherTalk.
 */

/* revision history 

 03-14-94  jjs 	Changed all functions which assumed only one port would
 		ever be used.  Added validate_msg_size, changed elap_online
		to work with the h/w name only (e.g. 'et2').

 Modified for MP, 1996 by Tuyen Nguyen
 Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.

*/

#define RESOLVE_DBG				/* for debug.h global resolution */
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
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/malloc.h>
#include <sys/sockio.h>
#include <vm/vm_kern.h>         /* for kernel_map */


#include <net/if.h>
#include <net/if_types.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/ddp.h>
#include <netat/lap.h>
#include <netat/routing_tables.h>     /* rtmp+zip table structs  */
#include <netat/zip.h>
#include <netat/nbp.h>
#include <netat/at_snmp.h>
#include <netat/at_pcb.h>
#include <netat/at_aarp.h>
#include <netat/asp.h>
#include <netat/atp.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

#include <sys/kern_event.h>

/* globals */

at_ifaddr_t at_interfaces[IF_TOTAL_MAX];
	/* index for at_interfaces is not important */
at_ifaddr_t  *ifID_table[IF_TOTAL_MAX];
	/* the table of ifID structures, one per interface 
	   (not just ethernet), 
	 * NOTE: for MH, entry 0 in this table is 
	 *       now defined to be the default I/F
	 */
at_ifaddr_t  *ifID_home;
	/* always ifID_table[IFID_HOME] for now, but will be used for
	   dynamic "home port" assignment, later */

at_state_t at_state;		/* global state of AT network */
snmpFlags_t snmpFlags;

int xpatcnt = 0;

/* snmp defines */
#define MAX_BUFSIZE	8192   
#define MAX_RTMP	(MAX_BUFSIZE/sizeof(RT_entry)-1)
#define MAX_NBP 		\
	((MAX_BUFSIZE - SNMP_NBP_HEADER_SIZE)/sizeof(snmpNbpEntry_t)-1)
#define MAX_NBP_BYTES	(MAX_NBP * sizeof(snmpNbpEntry_t))
#define MAX_ZIP		(MAX_BUFSIZE/sizeof(ZT_entry)-1)
#define MAX_RTMP_BYTES	(MAX_RTMP * sizeof(RT_entry))
#define MAX_ZIP_BYTES	(MAX_ZIP * sizeof(ZT_entry))

/* externs */
extern TAILQ_HEAD(name_registry, _nve_) name_registry;
extern snmpStats_t	snmpStats;
extern atlock_t ddpinp_lock;
extern atlock_t arpinp_lock;
extern short appletalk_inited;
extern int adspInited;
extern struct atpcb ddp_head;
extern gref_t *atp_inputQ[];
extern struct atp_state *atp_used_list;
extern asp_scb_t *asp_scbQ[];
extern asp_scb_t *scb_used_list;
extern CCB *adsp_inputQ[];
extern CCB *ccb_used_list;
extern at_ddp_stats_t at_ddp_stats;

/* protos */
extern snmpAarpEnt_t * getAarp(int *);
extern void nbp_shutdown(), routershutdown(), ddp_brt_shutdown();
extern void ddp_brt_init(), rtmp_init(), rtmp_input();
extern rtmp_router_start(at_kern_err_t *);
static void getIfNames(at_ifnames_t *);
static void add_route();
static int set_zones();
void elap_offline();
static int elap_online1(), re_aarp();
int at_reg_mcast(), at_unreg_mcast();
void  AARPwakeup(), ZIPwakeup();
static void elap_hangup();
static getSnmpCfg();

at_ifaddr_t *find_ifID(if_name)
	char	*if_name;
{
	int pat_id;
	  
	if (strlen(if_name))
		for (pat_id=0; pat_id < xpatcnt; pat_id++) {
			if (!strcmp(at_interfaces[pat_id].ifName, if_name))
				return(&at_interfaces[pat_id]);
		}

	return((at_ifaddr_t *)NULL);
}

static int validate_msg_size(m, gref, elapp)
	register gbuf_t *m;
	gref_t		*gref;
	at_ifaddr_t **elapp;

/* checks ioctl message type for minimum expected message size & 
   sends error back if size invalid
*/
{
	register ioc_t *iocbp;
	register at_if_cfg_t *cfgp;
	int i = 0, size = 1;
	
	*elapp = NULL;		
	iocbp = (ioc_t *) gbuf_rptr(m);

	dPrintf(D_M_ELAP, D_L_INFO, ("validate_msg_size: ioc_cmd = %d\n", 
				     iocbp->ioc_cmd));
	switch (iocbp->ioc_cmd) {
		case LAP_IOC_ADD_ROUTE:
			size = sizeof(RT_entry);
			break;
		case LAP_IOC_GET_ROUTE:
			size = sizeof(RT_entry);
			break;
		case LAP_IOC_GET_ZONE:
			size = sizeof(ZT_entryno);
			break;
		case LAP_IOC_SNMP_GET_CFG:
		case LAP_IOC_SNMP_GET_AARP:
		case LAP_IOC_SNMP_GET_ZIP:
		case LAP_IOC_SNMP_GET_RTMP:
		case LAP_IOC_SNMP_GET_NBP:
			size = sizeof(int);
			break;

		case ELAP_IOC_GET_STATS:
		case LAP_IOC_SNMP_GET_DDP:
			size = 0;
			break;

		default:
			dPrintf(D_M_ELAP, D_L_ERROR, ("validate_msg_size: unknown ioctl\n"));
			goto error;
	}

	if (size == 0) {				/* a non-data ioctl */
		return(0);
	}

	if (gbuf_cont(m) != NULL)
		i = gbuf_len(gbuf_cont(m));
	if (iocbp->ioc_count < size || (gbuf_cont(m) == NULL) || i < size) {
		dPrintf(D_M_ELAP, D_L_ERROR,
			("ioctl msg error:s:%d c:%d bcont:%c delta:%d\n",
			 size, iocbp->ioc_count,
			 gbuf_cont(m)? 'Y' : 'N', i));
		goto error;
	}
	else
		return(0);
error:
	ioc_ack(EMSGSIZE, m, gref);
	return (EMSGSIZE);
} /* validate_msg_size */

int lap_online(elapp, cfgp)
     at_ifaddr_t *elapp;
     at_if_cfg_t *cfgp;
{
	int error;

	if (elapp->ifState != LAP_OFFLINE) {
		return(EALREADY);
	}

	elapp->flags = 0;
	if (cfgp->flags & ELAP_CFG_HOME) {
		if (ifID_home)  {
			/* only 1 home allowed! */
			return(EEXIST);
		}
		dPrintf(D_M_ELAP, D_L_STARTUP, 
			("elap_wput home I/F:%s\n", cfgp->ifr_name));
		elapp->flags |= ELAP_CFG_HOME;
	}

	if (MULTIPORT_MODE) {
		elapp->flags |= ELAP_CFG_ZONELESS;
		if (ROUTING_MODE && cfgp->netStart)
			elapp->flags |= ELAP_CFG_SEED;
	}

	if (!DEFAULT_ZONE(&cfgp->zonename) &&
	    (elapp->flags & ELAP_CFG_HOME) || MULTIHOME_MODE) {
		elapp->startup_zone = cfgp->zonename;
	}

	if (elapp->flags & ELAP_CFG_SEED) {
		dPrintf(D_M_ELAP, D_L_STARTUP_INFO,
			("elap_wput: found to be seed\n"));
		elapp->ifThisCableStart = cfgp->netStart;
		elapp->ifThisCableEnd   = cfgp->netEnd;
	}
	else {
		dPrintf(D_M_ELAP,D_L_ERROR, 
			("elap_wput: we believe we're not seed\n"));
		/* from ELAP_IOC_SET_CFG */
		if (ATALK_VALUE(cfgp->node)) {
			u_short	initial_net;
			u_char	initial_node;

			initial_node = cfgp->node.s_node;
			initial_net = cfgp->node.s_net;
			if ((initial_node<0xfe) && (initial_node>0) &&
			    !((initial_net == 0) ||
			      ((initial_net >= DDP_STARTUP_LOW)&&
			       (initial_net <= DDP_STARTUP_HIGH)))) {

				elapp->initial_addr = cfgp->node;
			}
		}
	}

	elapp->startup_error = 0;
	elapp->startup_inprogress = FALSE;
	if ((error = elap_online1(elapp)))
		ddp_rem_if(elapp);
	else 
		if (!(MULTIPORT_MODE) &&
		    elapp->ifZoneName.len == 1 &&
		    elapp->ifZoneName.str[0] == '*' &&
		    !DEFAULT_ZONE(&cfgp->zonename)) {
			nbp_add_multicast(&cfgp->zonename, elapp);
		}
	return(error);
} /* lap_online */

/***********************************************************************
 * elap_wput()
 *
 **********************************************************************/
int elap_wput(gref, m)
     gref_t *gref;
     register gbuf_t	*m;
{
	at_ifaddr_t 	*elapp;
	register ioc_t		*iocbp;
	register at_if_cfg_t	*cfgp;
	at_elap_stats_t		*statsp;
	int error, i;
	int			(*func)();
	gbuf_t		*tmpm;
	at_ifaddr_t *patp;


	switch (gbuf_type(m)) {
	case MSG_DATA:
		gbuf_freem(m);
		dPrintf(D_M_ELAP,D_L_ERROR,
	       		("Output data to control channel is ignored\n"));
	break;

	case MSG_IOCTL:
		iocbp = (ioc_t *) gbuf_rptr(m);

	        if (validate_msg_size(m, gref, &elapp))
			break;	

		if (elapp)
			cfgp = (at_if_cfg_t*) gbuf_rptr(gbuf_cont(m));

		if (LAP_IOC_MYIOCTL(iocbp->ioc_cmd) || 
		    ELAP_IOC_MYIOCTL(iocbp->ioc_cmd)) {

			switch (iocbp->ioc_cmd) {
			case ELAP_IOC_GET_STATS:
#ifdef APPLETALK_DEBUG
				kprintf("LAP_IOC_GET_STATS\n");
#endif
				if ( (gbuf_cont(m) == NULL)
				     || (elapp = find_ifID(gbuf_rptr(gbuf_cont(m)))) == NULL) {
					ioc_ack(EINVAL, m, gref);
					break;
				}
				gbuf_freem(gbuf_cont(m));
				if ((gbuf_cont(m) =gbuf_alloc(sizeof(at_elap_stats_t), 
			    		PRI_MED)) == NULL) {
					ioc_ack(ENOBUFS, m, gref);
					break;
				}
				statsp = ((at_elap_stats_t *)gbuf_rptr(gbuf_cont(m)));
				*statsp = elapp->stats;
				gbuf_wset(gbuf_cont(m),sizeof(at_elap_stats_t));
				iocbp->ioc_count = sizeof(at_elap_stats_t);
				ioc_ack(0, m, gref);
				break;

			case LAP_IOC_ADD_ROUTE:
#ifdef APPLETALK_DEBUG
				kprintf("LAP_IOC_ADD_ROUTE\n");
#endif
				add_route((RT_entry *)gbuf_rptr(gbuf_cont(m)));
				ioc_ack(0, m, gref);
				break;

			case LAP_IOC_GET_ZONE:
#ifdef APPLETALK_DEBUG
			  kprintf("LAP_IOC_GET_ZONE\n");
#endif
			  /* return next ZT_entryno from ZT_table 
			     a pointer to the struct ZT_entryno is passed down from
			     user space and the first byte is cast to a int, if
			     this int is non-zero, then the first ZT_entry is
			     returned and subsequent calls with a zero value
			     will return the next entry in the table. The next
			     read after the last valid entry will return EINVAL
			  */
			{
				ZT_entryno *pZTe;

				i =  *(int *)gbuf_rptr(gbuf_cont(m));
				gbuf_freem(gbuf_cont(m));
				gbuf_cont(m) = NULL;

				pZTe = zt_getNextZone(i);
				if (pZTe) {
					if ((gbuf_cont(m) = gbuf_alloc(sizeof(ZT_entryno), PRI_MED)) == NULL) {
						ioc_ack(ENOBUFS, m, gref);
						break;
					}	
					*(ZT_entryno *)gbuf_rptr(gbuf_cont(m)) = *pZTe;
					gbuf_wset(gbuf_cont(m),sizeof(ZT_entryno));
					iocbp->ioc_count = sizeof(ZT_entryno);
					ioc_ack(0, m, gref);
				}
				else
					ioc_ack(EINVAL, m, gref);
			}
				break;

			case LAP_IOC_GET_ROUTE:
#ifdef APPLETALK_DEBUG
				kprintf("LAP_IOC_GET_ROUTE\n");
#endif
				/* return next RT_entry from RT_table 
				 * a pointer to the struct RT_entry is
				 * passed down from user space and the first
				 * byte is cast to a int, if this int is
				 * non-zero, then the first RT_entry is
				 * returned and subsequent calls with a
				 * zero value will return the next entry in
				 * the table. The next read after the last
				 * valid entry will return EINVAL
				 */
			{
				RT_entry *pRT;

				i =  *(int *)gbuf_rptr(gbuf_cont(m));
				gbuf_freem(gbuf_cont(m));
				gbuf_cont(m) = NULL;

				pRT = rt_getNextRoute(i);
				if (pRT) {
					if ((gbuf_cont(m) = gbuf_alloc(sizeof(RT_entry), PRI_MED)) == NULL) {
						ioc_ack(ENOBUFS, m, gref);
						break;
					}	
					*(RT_entry *)gbuf_rptr(gbuf_cont(m)) = *pRT;
					gbuf_wset(gbuf_cont(m),sizeof(RT_entry));
					iocbp->ioc_count = sizeof(RT_entry);
					ioc_ack(0, m, gref);
				}
				else
					ioc_ack(EINVAL, m, gref);
			}
				break;
			
			case LAP_IOC_SNMP_GET_DDP:
#ifdef APPLETALK_DEBUG
				kprintf("LAP_IOC_SNMP_GET_DDP\n");
#endif
				if (!(at_state.flags & AT_ST_STARTED)) {
					ioc_ack(ENOTREADY, m, gref);
					break;
				}
				if ((gbuf_cont(m) = gbuf_alloc(sizeof(snmpStats_t), 
						PRI_MED)) == NULL) {
					ioc_ack(ENOBUFS, m, gref);
					break;
				}
				
				*(snmpStats_t *)gbuf_rptr(gbuf_cont(m)) = snmpStats;
				gbuf_wset(gbuf_cont(m),sizeof(snmpStats));
				iocbp->ioc_count = sizeof(snmpStats);
				ioc_ack(0, m, gref);
				break;
			case LAP_IOC_SNMP_GET_CFG:
#ifdef APPLETALK_DEBUG
				kprintf("LAP_IOC_SNMP_GET_CFG\n");
#endif
			{
				int i,size;
				snmpCfg_t 	snmp;

				i =  *(int *)gbuf_rptr(gbuf_cont(m));
				gbuf_freem(gbuf_cont(m));
				gbuf_cont(m) = NULL;
				if (!(at_state.flags & AT_ST_STARTED)) {
					/* if stack down */
					iocbp->ioc_count = 0;
					ioc_ack(ENOTREADY, m, gref);
					dPrintf(D_M_ELAP_LOW, D_L_INFO,
						("elap_wput: cfg req, stack down\n"));
					break;
				}
				if (i == UPDATE_IF_CHANGED && 
					!(at_state.flags & AT_ST_IF_CHANGED)) {
					iocbp->ioc_count = 0;
					ioc_ack(0, m, gref);
					dPrintf(D_M_ELAP_LOW, D_L_INFO,
						("elap_wput: cfg req, unchanged\n"));
					break;
				}
				dPrintf(D_M_ELAP_LOW, D_L_INFO,
					("elap_wput: cfg req, changed\n"));

				if (getSnmpCfg(&snmp)) {
					dPrintf(D_M_ELAP,D_L_ERROR,
						("elap_wput:SNMP_GET_CFG error\n"));
					ioc_ack(EOPNOTSUPP, m, gref);
					break;
				}
					/* send up only used part of table */
				size = sizeof(snmp) - 
					   sizeof(snmpIfCfg_t) * (MAX_IFS - snmp.cfg_ifCnt);

				if ((gbuf_cont(m) = gbuf_alloc(size, PRI_MED)) == NULL) {
					ioc_ack(ENOBUFS, m, gref);
					break;
				}
				bcopy(&snmp,gbuf_rptr(gbuf_cont(m)),size);
				gbuf_wset(gbuf_cont(m),size);
				iocbp->ioc_count = size;
				at_state.flags &= ~AT_ST_IF_CHANGED;
				ioc_ack(0, m, gref);
			}
			break;

			case LAP_IOC_SNMP_GET_AARP:
			{
				snmpAarpEnt_t *snmpp;
				int bytes;
#ifdef APPLETALK_DEBUG
				kprintf("LAP_IOC_SNMP_GET_AARP\n");
#endif
				i =  *(int *)gbuf_rptr(gbuf_cont(m));
				gbuf_freem(gbuf_cont(m));
				gbuf_cont(m) = NULL;
				dPrintf(D_M_ELAP,D_L_INFO,
					("elap_wput:calling getarp,i=%d\n", i));
				snmpp = getAarp(&i); 
				bytes = i * sizeof(snmpAarpEnt_t);
				dPrintf(D_M_ELAP,D_L_INFO,
					("elap_wput:getarp returned, i=%d,bytes=%d\n", 
					i, bytes));
				if (snmpp) {
					if ((gbuf_cont(m) = gbuf_alloc(bytes, PRI_MED)) == NULL) {
						ioc_ack(ENOBUFS, m, gref);
						break;
					}	
					bcopy(snmpp, gbuf_rptr(gbuf_cont(m)), bytes);
					gbuf_wset(gbuf_cont(m),bytes);
					iocbp->ioc_count = bytes;
					ioc_ack(0, m, gref);
				}
				else
					ioc_ack(EOPNOTSUPP, m, gref);
			}
			break;

			case LAP_IOC_SNMP_GET_ZIP:
#ifdef APPLETALK_DEBUG
				kprintf("LAP_IOC_SNMP_GET_ZIP\n");
#endif
			{ /* matching brace NOT in this case */
				register int i,j;
				register int size, total, tabsize;
				gbuf_t	*mn;		/* new gbuf */
				gbuf_t	*mo;		/* old gbuf */
				gbuf_t	*mt;		/* temp */
				snmpNbpTable_t		*nbp;

				i =  *(int *)gbuf_rptr(gbuf_cont(m));
				gbuf_freem(gbuf_cont(m));
				gbuf_cont(m) = NULL;
				if (!(at_state.flags & AT_ST_STARTED)) {
					ioc_ack(ENOTREADY, m, gref);
					break;
				}
				if (i == UPDATE_IF_CHANGED && 
					!(at_state.flags & AT_ST_ZT_CHANGED)) {
					iocbp->ioc_count = 0;
					ioc_ack(0, m, gref);
					break;
				}
				mo=(gbuf_t*)NULL;
				tabsize = getZipTableSize();

					/* retrieve table into multiple gbufs */
				for (i =0; i<tabsize;  i+=j) {
					j = tabsize - i > 
						MAX_ZIP ? MAX_ZIP : tabsize - i;
					size = j < MAX_ZIP ? sizeof(ZT_entry)*j : MAX_ZIP_BYTES;
					if ((mn = gbuf_alloc(size, PRI_MED)) == NULL) {
						if (gbuf_cont(m))
							gbuf_freem(gbuf_cont(m));
						ioc_ack(ENOBUFS, m, gref);
						break;
					}
					if (!mo)	{ 		/* if first new one */
						mt = mn;
						total = size;
					}
					else {
						gbuf_cont(mo) = mn;
						total += size;
					}
					mo = mn;
					getZipTable((ZT_entry*)gbuf_rptr(mn),i,j); 
					gbuf_wset(mn,size);
				}
				if ((gbuf_cont(m) = gbuf_alloc(sizeof(int), PRI_MED)) == NULL) {
					if (mt)
						gbuf_freem(mt);
					iocbp->ioc_count = 0;
					ioc_ack(ENOBUFS, m, gref);
					break;
				}
				if (!tabsize) {
					dPrintf(D_M_ELAP,D_L_WARNING,
						("elap_wput:snmp: empty zip table\n"));
					total = 0;
				}
				*(int*)gbuf_rptr(gbuf_cont(m)) = total; 	/* return table size */
				gbuf_wset(gbuf_cont(m),sizeof(int));
				iocbp->ioc_count = sizeof(int);
				ioc_ack(0, m, gref);
				if (tabsize)
					atalk_putnext(gref,mt);		/* send up table */
				at_state.flags &= ~AT_ST_ZT_CHANGED;
				break;

			case LAP_IOC_SNMP_GET_RTMP:
#ifdef APPLETALK_DEBUG
				kprintf("LAP_IOC_SNMP_GET_RTMP\n");
#endif
				i =  *(int *)gbuf_rptr(gbuf_cont(m));
				gbuf_freem(gbuf_cont(m));
				gbuf_cont(m) = NULL;
				if (!(at_state.flags & AT_ST_STARTED)) {
					ioc_ack(ENOTREADY, m, gref);
					break;
				}
				if (i == UPDATE_IF_CHANGED && 
				    !(at_state.flags & AT_ST_RT_CHANGED)) {
					iocbp->ioc_count = 0;
					ioc_ack(0, m, gref);
					break;
				}

				mo=(gbuf_t*)NULL;
				tabsize = getRtmpTableSize();

					/* retrieve table into multiple gbufs */
				for (i =0; i<tabsize;  i+=j) {
					j = tabsize - i > 
						MAX_RTMP ? MAX_RTMP : tabsize - i;
					size = j < MAX_RTMP ? sizeof(RT_entry)*j : MAX_RTMP_BYTES;
					if ((mn = gbuf_alloc(size, PRI_MED)) == NULL) {
						if (gbuf_cont(m))
							gbuf_freem(gbuf_cont(m));
						ioc_ack(ENOBUFS, m, gref);
						break;
					}
					if (!mo)	{ 		/* if first new one */
						mt = mn;
						total = size;
					}
					else {
						gbuf_cont(mo) = mn;
						total += size;
					}
					mo = mn;
					getRtmpTable((RT_entry*)gbuf_rptr(mn),i,j); 
					gbuf_wset(mn,size);
				}
				if ((gbuf_cont(m) = gbuf_alloc(sizeof(int), PRI_MED)) == NULL) {
					if (mt)
						gbuf_freem(mt);
					iocbp->ioc_count = 0;
					ioc_ack(ENOBUFS, m, gref);
					break;
				}
				if (!tabsize)
					total = 0;
				*(int*)gbuf_rptr(gbuf_cont(m)) = total;	/* return table size */
				gbuf_wset(gbuf_cont(m),sizeof(int));
				iocbp->ioc_count = sizeof(int);
				ioc_ack(0, m, gref);
				if (tabsize)
					atalk_putnext(gref,mt);		/* send up table */
				at_state.flags &= ~AT_ST_RT_CHANGED;
				break;

			case LAP_IOC_SNMP_GET_NBP:
#ifdef APPLETALK_DEBUG
				kprintf("LAP_IOC_SNMP_GET_NBP\n");
#endif
				i =  *(int *)gbuf_rptr(gbuf_cont(m));
				gbuf_freem(gbuf_cont(m));
				gbuf_cont(m) = NULL;
				if (!(at_state.flags & AT_ST_STARTED)) {
					ioc_ack(ENOTREADY, m, gref);
					break;
				}
				if (i == UPDATE_IF_CHANGED && 
				    !(at_state.flags & AT_ST_NBP_CHANGED)) {
					iocbp->ioc_count = 0;
					ioc_ack(0, m, gref);
					dPrintf(D_M_ELAP_LOW, D_L_INFO,
						("elap_wput: nbp req denied, no change\n"));
					break;
				}

				mo=(gbuf_t*)NULL;
				tabsize = getNbpTableSize();

					/* retrieve table into multiple gbufs */
				for (i =0; i<tabsize;  i+=j) {
					j = tabsize - i > 
						MAX_NBP ? MAX_NBP : tabsize - i;
					size = j < MAX_NBP ? sizeof(snmpNbpEntry_t)*j : MAX_NBP_BYTES;
					if (!i)
						size += SNMP_NBP_HEADER_SIZE;
					if ((mn = gbuf_alloc(size, PRI_MED)) == NULL) {
						if (gbuf_cont(m))
							gbuf_freem(gbuf_cont(m));
						ioc_ack(ENOBUFS, m, gref);
						break;
					}
					if (!mo)	{ 		/* if first new one */
						mt = mn;
						total = size;
						nbp = (snmpNbpTable_t*)gbuf_rptr(mn);
						nbp->nbpt_entries = tabsize;
						nbp->nbpt_zone = ifID_home->ifZoneName;
						getNbpTable(nbp->nbpt_table,i,j); 
					}
					else {
						gbuf_cont(mo) = mn;
						total += size;
						getNbpTable((snmpNbpEntry_t *)gbuf_rptr(mn),i,j); 
					}
					mo = mn;
					gbuf_wset(mn,size);
				}
				if ((gbuf_cont(m) = gbuf_alloc(sizeof(int), PRI_MED)) == NULL) {
					if (mt)
						gbuf_freem(mt);
					iocbp->ioc_count = 0;
					ioc_ack(ENOBUFS, m, gref);
					break;
				}
				if (!tabsize)
					total = 0;
				*(int*)gbuf_rptr(gbuf_cont(m)) = total;	/* return table size */
				gbuf_wset(gbuf_cont(m),sizeof(int));
				iocbp->ioc_count = sizeof(int);
				ioc_ack(0, m, gref);
				if (tabsize)
					atalk_putnext(gref,mt);		/* send up table */
				at_state.flags &= ~AT_ST_NBP_CHANGED;
				break;
			}
				
			default:
#ifdef APPLETALK_DEBUG
				kprintf("unknown ioctl %d\n", iocbp->ioc_cmd);
#endif
				ioc_ack(ENOTTY, m, gref);
				dPrintf(D_M_ELAP, D_L_WARNING,
					("elap_wput: unknown ioctl (%d)\n", iocbp->ioc_cmd));

				if (elapp)
					elapp->stats.unknown_mblks++;
				break;
			}
		}
		break;

	default:
		gbuf_freem(m);
		break;
	}

	return 0;
} /* elap_wput */


/* Called directly by ddp/zip.
 */
elap_dataput(m, elapp, addr_flag, addr)
     register	gbuf_t	*m;
     register at_ifaddr_t *elapp;
     u_char	addr_flag;
     char *addr;
{
	register int		size;
	int			error;
	extern	int		zip_type_packet();
	struct	etalk_addr	dest_addr;
	struct	atalk_addr	dest_at_addr;
	extern	gbuf_t		*growmsg();
	int			loop = TRUE;
				/* flag to aarp to loopback (default) */

	/* the incoming frame is of the form {flag, address, ddp...}
	 * where "flag" indicates whether the address is an 802.3
	 * (link) address, or an appletalk address.  If it's an
	 * 802.3 address, the packet can just go out to the network
	 * through PAT, if it's an appletalk address, AT->802.3 address
	 * resolution needs to be done.
	 * If 802.3 address is known, strip off the flag and 802.3
	 * address, and prepend 802.2 and 802.3 headers.
	 */
	
	if (addr == NULL) {
		addr_flag = *(u_char *)gbuf_rptr(m);
		gbuf_rinc(m,1);
	}
	
	switch (addr_flag) {
	case AT_ADDR_NO_LOOP :
		loop = FALSE;
		/* pass thru */
	case AT_ADDR :
	if (addr == NULL) {
	    dest_at_addr = *(struct atalk_addr *)gbuf_rptr(m);
	    gbuf_rinc(m,sizeof(struct atalk_addr));
	} else
	    dest_at_addr = *(struct atalk_addr *)addr;
	    break;
	case ET_ADDR :
	if (addr == NULL) {
	    dest_addr = *(struct etalk_addr *)gbuf_rptr(m);
	    gbuf_rinc(m,sizeof(struct etalk_addr));
	} else
	    dest_addr = *(struct etalk_addr *)addr;
	    break;
	default :
	    gbuf_freel(m);		/* unknown address type, chuck it */
	    return(EINVAL);
        }

	m = gbuf_strip(m);

	/* At this point, rptr points to ddp header for sure */
	if (elapp->ifState == LAP_OFFLINE) {
	    gbuf_freel(m);
		return(ENETDOWN);
	}

	if (elapp->ifState == LAP_ONLINE_FOR_ZIP) {
		/* see if this is a ZIP packet that we need
		 * to let through even though network is
		 * not yet alive!!
		 */
		if (zip_type_packet(m) == 0) {
		    	gbuf_freel(m);
			return(ENETDOWN);
		}
	}
	
	elapp->stats.xmit_packets++;
	size = gbuf_msgsize(m);
	elapp->stats.xmit_bytes += size;
	snmpStats.dd_outLong++;
	
	switch (addr_flag) {
	case AT_ADDR_NO_LOOP :
	case AT_ADDR :
	    /*
	     * we don't want elap to be looking into ddp header, so
	     * it doesn't know net#, consequently can't do 
	     * AMT_LOOKUP.  That task left to aarp now.
	     */
	    error = aarp_send_data(m,elapp,&dest_at_addr, loop);
	    break;
	case ET_ADDR :
	    error = pat_output(elapp, m, &dest_addr, 0);
	    break;
        }
	return (error);
} /* elap_dataput */

/************************************************************************
 * elap_online()
 *
 ************************************************************************/

static int elap_online1(elapp)
     at_ifaddr_t *elapp;
{
	int errno;

	dPrintf(D_M_ELAP, D_L_STARTUP_INFO, ("elap_online:%s elapp:0x%x\n",
		(elapp->ifName) ? &elapp->ifName[0] : "NULL interface", (u_int) elapp));
	if (elapp->ifState != LAP_OFFLINE || elapp->startup_inprogress == TRUE)
	        return (EALREADY);
	
	at_state.flags |= AT_ST_IF_CHANGED;

	if (elapp->flags & ELAP_CFG_HOME) /* tell ddp_add_if if this is home */
		elapp->ifFlags |= AT_IFF_DEFAULT;
		
	/* Get DDP started */
	if ((errno = ddp_add_if(elapp)))
		return(errno);

	/* set up multicast address for cable-wide broadcasts */
	(void)at_reg_mcast(elapp, (caddr_t)&elapp->cable_multicast_addr);

	elapp->startup_inprogress = TRUE;
	if (! (elapp->startup_error = re_aarp(elapp)))
		(void)tsleep(&elapp->startup_inprogress, PSOCK | PCATCH, 
			     "elap_online1", 0);

	/* then later, after some timeouts AARPwakeup() is called */

	return(elapp->startup_error);
} /* elap_online1 */

static int re_aarp(elapp)
     at_ifaddr_t *elapp;
{
	int errno;

	/* We now call aarp_init() to assign an appletalk node addr */
	errno = aarp_init1(elapp);
			/* aarp_init1() returns either -1 or ENOTREADY */
	if (errno == ENOTREADY)
		return(0);
	else {
		dPrintf(D_M_ELAP, D_L_STATE_CHG, 
			("elap_online aarp_init for %s\n", elapp->ifName));
		(void)at_unreg_mcast(elapp, (caddr_t)&elapp->cable_multicast_addr);
		ddp_rem_if(elapp);
		elapp->ifState = LAP_OFFLINE;
		return(EADDRNOTAVAIL);
	}
}

/* called from AARPwakeup */
static void elap_online2(elapp)
     at_ifaddr_t *elapp;
{
	if (MULTIPORT_MODE) {
		dPrintf(D_M_ELAP,D_L_STARTUP_INFO, 
			("elap_online: re_aarp, we know it's a router...\n"));

		if (elapp->flags & ELAP_CFG_SEED) {
			/* add route table entry (zones to be added later) */
			dPrintf(D_M_ELAP, D_L_STARTUP_INFO,
				("elap_online: rt_insert Cable %d-%d port =%d as SEED\n",
				elapp->ifThisCableStart, elapp->ifThisCableEnd, elapp->ifPort));
			rt_insert(elapp->ifThisCableEnd,
				  elapp->ifThisCableStart,
				  0,0,0,
				  elapp->ifPort,
				  RTE_STATE_PERMANENT | RTE_STATE_ZKNOWN | RTE_STATE_GOOD
					 );
			/* LD 081694: set the RTR_SEED_PORT flag for seed ports */
			elapp->ifFlags |= RTR_SEED_PORT;
		}
		else 
			dPrintf(D_M_ELAP,D_L_STARTUP_INFO,
				("elap_online: it's a router, but non seed\n"));
	}

	if (elapp->flags & ELAP_CFG_ZONELESS) {
		/* ELAP_CFG_ZONELESS tells us that it is a router or in
		       multihome mode, so we don't want to do the GetNetInfo
		       exchange with the router.  */

		elapp->ifState = LAP_ONLINE_ZONELESS;
		elapp->startup_inprogress = FALSE;
		wakeup(&elapp->startup_inprogress);
		dPrintf(D_M_ELAP, D_L_STARTUP_INFO, ("elap_online: ack 3\n"));
		return;
	}

	/* if we don't already have a zone and a multicast address */
	if (*(int *)&elapp->ZoneMcastAddr == 0 || elapp->ifZoneName.len == 0) {
		/* hzonehash is a global containing the nbp hash for the startup_zone */
		sethzonehash(elapp);

		/* Get ZIP rolling to get zone multicast address, etc. */
		elapp->ifState = LAP_ONLINE_FOR_ZIP;
		(void)zip_control(elapp, ZIP_ONLINE);
		/* zip_control (w. control == ZIP_ONLINE) always returns ENOTREADY */

		/* later, after some timeouts ZIPwakeup() is called. */
	} else {
		/* otherwise, we have the zone and the multicast already,
		   so don't bother with another ZIP GetNetInfo request */
		ZIPwakeup(elapp, 0);
	}
} /* elap_online2 */

/* called from rtmp_router_start */
int elap_online3(elapp)
     at_ifaddr_t	*elapp;
{
	elapp->startup_inprogress = TRUE;

	/* just reset the net range */
	elapp->initial_addr.s_net = 0;
	elapp->initial_addr.s_node = 0;
	dPrintf(D_M_ELAP_LOW, D_L_STARTUP_INFO,
		("elap_online: goto re_aarp port=%d\n", elapp->ifPort));

	if ((elapp->startup_error = re_aarp(elapp)))
		return(elapp->startup_error);

	/* then later, after some timeouts AARPwakeup() is called */

	(void)tsleep(&elapp->startup_inprogress, PSOCK | PCATCH, 
		     "elap_online3", 0);
	return(elapp->startup_error);
} /* elap_online3 */

/****************************************************************************
 * elap_offline()
 *
 ****************************************************************************/

void elap_offline(elapp)
     register at_ifaddr_t *elapp;

{
	void	zip_sched_getnetinfo(); /* forward reference */
	int	errno;
	int s;

	dPrintf(D_M_ELAP, D_L_SHUTDN_INFO, ("elap_offline:%s\n", elapp->ifName));
	if (elapp->ifState != LAP_OFFLINE) {

		/* Since AppleTalk is going away, remove the cable
		 * multicast address  and turn the interface off so that all 
		 * AppleTalk packets are dropped in the driver itself.
		 * Get rid of the zone multicast address prior to going Offline.
		 */
		(void)at_unreg_mcast(elapp, (caddr_t)&elapp->ZoneMcastAddr);
		(void)at_unreg_mcast(elapp, (caddr_t)&elapp->cable_multicast_addr);
		elapp->ifState = LAP_OFFLINE;

		ATDISABLE(s, ddpinp_lock);
		if (MULTIPORT_MODE)
			RT_DELETE(elapp->ifThisCableEnd,
				  elapp->ifThisCableStart);
		ATENABLE(s, ddpinp_lock);

		/* make sure no zip timeouts are left running */
		untimeout(zip_sched_getnetinfo, elapp);
	}
	ddp_rem_if(elapp);
} /* elap_offline */


static void add_route(rt)
RT_entry 	*rt;

/* support ioctl to manually add routes to table. 
   this is really only for testing
*/
{
	rt_insert( 	rt->NetStop, rt->NetStart, rt->NextIRNet, 
			 	rt->NextIRNode, rt->NetDist, rt->NetPort, 
			 	rt->EntryState);
	dPrintf(D_M_ELAP, D_L_STARTUP_INFO, ("adding route: %ud:%ud dist:%ud\n",
		rt->NetStart, rt->NetStop,rt->NetDist));
}

/*
 * ddp_start()
 *
 * Initialization that takes place each time AppleTalk is restarted.
 *
 */
void ddp_start()
{
	TAILQ_INIT(&at_ifQueueHd);
	TAILQ_INIT(&name_registry);
	bzero(at_interfaces, sizeof(at_interfaces));
	bzero(ifID_table, sizeof(ifID_table));
	bzero(&at_ddp_stats, sizeof(at_ddp_stats_t));
	rtmp_init(); /* initialize trackedrouters */

	add_ddp_handler(RTMP_SOCKET, rtmp_input);
	ifID_home = (at_ifaddr_t *)NULL;
	xpatcnt = 0;
}

int ddp_shutdown(count_only)
     int count_only;
{
	at_ifaddr_t *ifID;
	asp_scb_t *scb, *scb_next;
	struct atp_state *atp, *atp_next;
	CCB *sp, *sp_next;
	gref_t *gref;
	vm_offset_t temp_rcb_data, temp_state_data;
	int i, s, active_skts = 0;	/* count of active pids for non-socketized
				   AppleTalk protocols */
	extern int aarp_sched_probe();


	/* Network is shutting down... send error messages up on each open
	 * socket.
	 *** For now, for ASP, ATP and ADSP, attempt to notify open 
	     sockets, but return EBUSY and don't complete shutdown. *** 
	 */

	s = splimp();	/* *** previously contained mismatched locking 
			   that was ifdef'ed to splimp() *** */
	if (!count_only)
		nbp_shutdown();	/* clear all known NVE */

	/* ASP */
	for (scb = scb_used_list; scb; ) {
	    scb_next = scb->next_scb;
	    active_skts++;
	    if (!count_only) {
		dPrintf(D_M_ASP, D_L_TRACE, ("asp pid=%d\n", scb->pid));
	        atalk_notify(scb->gref, ESHUTDOWN);
	    }
	    scb = scb_next; 
	}
	for (i = 0; i < 256 ; i++) {
	    if ((scb = asp_scbQ[i]))
		do {
		    scb_next = scb->next_scb;
		    active_skts++;
		    if (!count_only) {
			dPrintf(D_M_ASP, D_L_TRACE, 
				("asp pid=%d\n", scb->pid));
		        atalk_notify(scb->gref, ESHUTDOWN);
		    }
		    scb = scb_next;
		} while (scb);
	}

	/* ATP */
	for (atp = atp_used_list; atp; ) {
	    atp_next = atp->atp_trans_waiting;
	    active_skts++;
	    if (!count_only) {
		dPrintf(D_M_ATP, D_L_TRACE, ("atp pid=%d\n", atp->atp_pid));
	        atalk_notify(atp->atp_gref, ESHUTDOWN);
	    }
	    atp = atp_next;
	}
	for (i = 0; i < 256; i++) {
	  if ((gref = atp_inputQ[i]) && (gref != (gref_t *)1)) {
		atp = (struct atp_state *)gref->info;	
		if (!atp->dflag) {
		    active_skts++;
		    if (!count_only) {
			dPrintf(D_M_ATP, D_L_TRACE, 
				("atp pid=%d\n", atp->atp_pid));
		        atalk_notify(atp->atp_gref, ESHUTDOWN);
		    }
		}
	  }
	}
	
	/* ADSP */
	for (sp = ccb_used_list; sp ; ) {
	    sp_next = sp->otccbLink;
	    active_skts++;
	    if (!count_only) {
		dPrintf(D_M_ADSP, D_L_TRACE, ("adsp pid=%d\n", sp->pid));
		atalk_notify(sp->gref, ESHUTDOWN);
	    }
	    sp = sp_next;
	}
	for (i = 0; i < 256 ; i++) {
	    if ((sp = adsp_inputQ[i]))
		do {
		    sp_next = sp->otccbLink;
		    active_skts++;
		    if (!count_only) {
			dPrintf(D_M_ADSP, D_L_TRACE, 
				("adsp pid=%d\n", sp->pid));
			atalk_notify(sp->gref, ESHUTDOWN);
		    }
		    sp = sp_next;
		} while (sp);
	}

	/* DDP */
	for (gref = ddp_head.atpcb_next; gref != &ddp_head; 
	     gref = gref->atpcb_next) {
	    if (count_only) {
		active_skts++;
	    } else {
		dPrintf(D_M_DDP,D_L_TRACE, ("ddp pid=%d\n", gref->pid));
		atalk_notify(gref, ESHUTDOWN);
	    }
	}
	if (count_only || active_skts) {
		splx(s);
		return(active_skts);

	}
	/* if there are no interfaces in the process of going online, continue shutting down DDP */
	for (i = 0; i < IF_TOTAL_MAX; i++) {
		if (at_interfaces[i].startup_inprogress == TRUE)
		        return(1);
	}
	if (MULTIPORT_MODE) {
                rtmp_shutdown();
                /* free memory allocated for the rtmp/zip tables */
		if (ZT_table) {
			FREE(ZT_table, M_RTABLE);
			ZT_table = (ZT_entry *)NULL;
		}
		if (RT_table) {
			FREE(RT_table, M_RTABLE);
			RT_table = (RT_entry *)NULL;
		}
	}          

	at_state.flags = 0;     /* make sure inits are done on restart */
	
	wakeup(&ifID_home->startup_inprogress);	/* if rtmp_router_start still starting up */

	/* from original ddp_shutdown() */
	routershutdown();
	ddp_brt_shutdown();

	if (adspInited) {
		CleanupGlobals();
		adspInited = 0;
	}
	
	 
	dPrintf(D_M_DDP, D_L_VERBOSE, ("DDP shutdown completed"));

	/*
	 * make sure we don't have a probe timeout hanging around
	 * it's going to try and make use of an entry in at_interfaces
	 * which is going to be zero'd out by the call to ddp_start a
	 * little further down
	 */
	untimeout(aarp_sched_probe, 0);

	/* *** after an SIOCSIFADDR and before an AIOCSIFADDR,
	       this is the only place to find the ifID *** */
	for (i = 0; i < IF_TOTAL_MAX; i++) {
		ifID = &at_interfaces[i];
		/* do LAP_IOC_OFFLINE processing */
		elap_offline(ifID);
	}
	ddp_start();
	
	/* free buffers for large arrays used by atp.
	 * to prevent a race condition if the funnel is dropped
	 * while calling kmem_free, the fields are grabbed and
	 * zeroed first.
	 */
	if (atp_rcb_data != NULL) {
		temp_rcb_data = (vm_offset_t)atp_rcb_data; 
		atp_rcb_data = NULL;
		atp_rcb_free_list = NULL;
	} else
	        temp_rcb_data = NULL;
	if (atp_state_data != NULL) {
		temp_state_data = (vm_offset_t)atp_state_data;
		atp_state_data = NULL;
		atp_free_list = NULL;
	} else
	        temp_state_data = NULL;

	if (temp_rcb_data)
	  kmem_free(kernel_map, temp_rcb_data, sizeof(struct atp_rcb) * NATP_RCB);
	if (temp_state_data)
	  kmem_free(kernel_map, temp_state_data, sizeof(struct atp_state) * NATP_STATE);

	splx(s);
	return(0);
} /* ddp_shutdown */

int routerStart(keP)
     at_kern_err_t *keP;
{
	register at_ifaddr_t *ifID;
	int error;

	if (! ifID_home)
		return(EINVAL);

	/*
	 * this will cause the ports to glean from the net the relevant
	 * information before forwarding
	 */
	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
		dPrintf(D_M_ELAP, D_L_STARTUP_INFO, 
			("routerStart Port %d (%s) set to activating\n",
			 ifID->ifPort, ifID->ifName));
		ifID->ifRoutingState = PORT_ACTIVATING;
		ifID->ifFlags |= RTR_XNET_PORT;
	}

	/*
	 * The next step is to check the information for each port before
	 * declaring the ports up and forwarding
	 */
	dPrintf(D_M_ELAP, D_L_STARTUP_INFO,
		("router_start: waiting 20 sec before starting up\n"));

	/* sleep for 20 seconds */
	if ((error = 
	     /* *** eventually this will be the ifID for the interface
		being brought up in router mode *** */
	     tsleep(&ifID_home->startup_inprogress, 
		    PSOCK | PCATCH, "routerStart", 20 * SYS_HZ))
	    != EWOULDBLOCK) {
/*
		if (!error)
			panic("routerStart: spurious interrupt");
*/
		return(error);
	}

	return(rtmp_router_start(keP));
	/* was timeout(rtmp_router_start, 0, 20 * SYS_HZ);  */
} /* routerStart */

void ZIPwakeup(elapp, ZipError)
     at_ifaddr_t *elapp;
     int ZipError;
{
	int s, error = ZipError;

	ATDISABLE(s, ddpinp_lock);
	if ( (elapp != NULL) && elapp->startup_inprogress) {
		ATENABLE(s, ddpinp_lock);

		/* was ZIPContinue */
		/* was elapp_online() with jump to ZIP_sleep */

		/* instead of the goto ZIP_sleep ... */
		switch (ZipError) {
			case 0 : /* success */
			    elapp->ifState = LAP_ONLINE;

				/* Send event with zone info. */
				atalk_post_msg(elapp->aa_ifp, KEV_ATALK_ZONEUPDATED, 0, &(elapp->ifZoneName));
				
			    break;
			case ZIP_RE_AARP :
			    /* instead of goto re_aarp; */
			    /* We now call aarp_init() to assign an 
			       appletalk node addr */
			    if ((elapp->startup_error = re_aarp(elapp))) {
				elapp->startup_inprogress = FALSE;
				wakeup(&elapp->startup_inprogress);
				dPrintf(D_M_ELAP, D_L_STARTUP_INFO, 
					("elap_online: ack 2\n"));
			    }
			    break;
			default :
			    break;
		}
		if (ZipError != ZIP_RE_AARP) {
			elapp->startup_error = error;
			elapp->startup_inprogress = FALSE;
			wakeup(&elapp->startup_inprogress);
			dPrintf(D_M_ELAP, D_L_STARTUP_INFO,
				("elap_online: ifZipError=%d\n", error));
		}
	} else
		ATENABLE(s, ddpinp_lock);
} /* ZIPwakeup */

void AARPwakeup(probe_cb)
     aarp_amt_t *probe_cb;
{
	int s;
	int errno;
	at_ifaddr_t *elapp;

	ATDISABLE(s, arpinp_lock);
	elapp = probe_cb->elapp;
	if ( (elapp != NULL) && elapp->startup_inprogress ) {
		ATENABLE(s, arpinp_lock);

		/* was AARPContinue */
		errno = aarp_init2(elapp);
		/* aarp_init2() returns either -1 or 0 */
		if (errno != 0) {
			dPrintf(D_M_ELAP, D_L_STATE_CHG, 
				("elap_online aarp_init for %s\n",
				 elapp->ifName));
			(void)at_unreg_mcast(elapp, (caddr_t)&elapp->ZoneMcastAddr);
			(void)at_unreg_mcast(elapp, (caddr_t)&elapp->cable_multicast_addr);
			elapp->ifState = LAP_OFFLINE;
			ddp_rem_if(elapp);
			elapp->startup_error = EADDRNOTAVAIL;
			elapp->startup_inprogress = FALSE;
			wakeup(&elapp->startup_inprogress);
			dPrintf(D_M_ELAP, D_L_STARTUP_INFO, ("elap_online: ack 2\n"));
		} else {
			dPrintf(D_M_ELAP,D_L_STARTUP_INFO,
				("elap_online: aarp_init returns zero\n"));
			elap_online2(elapp);
		}
	} else
		ATENABLE(s, arpinp_lock);
} /* AARPwakeup */

void ddp_bit_reverse(addr)
	unsigned char *addr;
{
static unsigned char reverse_data[] = {
	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
	0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
	0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
	0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
	0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
	0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
	0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
	0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
	0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
	0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
	0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
	0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
	0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
	0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
	0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
	0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
	0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
	0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
	0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
	0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
	0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
	0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
	0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
	0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
	0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
	0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
	0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
	0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
	0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
	0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
	0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
	0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff
	};

	unsigned char k;

	for (k=0; k < 6; k++)
		addr[k] = reverse_data[addr[k]];
}

static int elap_trackMcast(patp, func, addr)
	at_ifaddr_t    *patp;
	int func;
	caddr_t addr;
{
	int i, loc=-1;
	u_char c;
	switch(patp->aa_ifp->if_type) {
	case IFT_ETHER: 
	case IFT_FDDI: 
		/* set addr to point to unique part of addr */
		c = addr[5];

		/* first try to find match */
		/* *** save just one byte of the multicast address? *** */
		for (i=0; i< MAX_MCASTS; i++) 
			if (c == patp->mcast[i]) {
				loc = i;
				break;
			}
				
		switch (func) {
		case MCAST_TRACK_DELETE:
			if (loc >= 0) 
				patp->mcast[loc] = 0;

			break;
		case MCAST_TRACK_ADD:
			dPrintf(D_M_PAT_LOW, D_L_USR2, ("mctrack:add loc:%d\n", i));
			if (loc >= 0) {
				dPrintf(D_M_PAT_LOW, D_L_USR2, ("mctrack:add, addr was there\n"));
				return(1);
				break;			/* already there */
			}		
			for (i=0; i< MAX_MCASTS; i++) 
				if (patp->mcast[i] == 0) {
					loc = i;
					break;
				}
			dPrintf(D_M_PAT_LOW, D_L_USR2, ("mctrack:add1 loc:%d\n", i));
			if (loc >= 0) {
				patp->mcast[loc] = c;
				dPrintf(D_M_PAT_LOW, D_L_USR2, ("mctrack:add, adding(%x)\n",
					(*(int*)addr)&0xffffff));
			}
			else {
				/*errno = ENOMEM; */ /*LD 5/7/97 nobody is using that */
				return(-1);
			}
			break;	
		case MCAST_TRACK_CHECK:
			if (loc >= 0) {
				dPrintf(D_M_PAT_LOW, D_L_USR2, ("mctrack:check, addr was there\n"));
				return(0);
			}
			else {
				dPrintf(D_M_PAT_LOW, D_L_USR2, ("mctrack:add, addr was NOT there\n"));
				return(-1);
			}
			
		default:
			/*errno = EINVAL;*/ /*LD 5/7/97 nobody is using that */
			return(-1);
		}

	case IFT_ISO88025: /* token ring */
		/* we would use the lowest byte of the addr argument as a value
		   to shift left a 1 to form the mcast mask for TR. We'll do this
		   when the time comes
		 */
	default:
		;
	}
	return(0);
}


static getSnmpCfg(snmp)
	snmpCfg_t *snmp;
{
	int i;
	at_ifaddr_t 	*elapp;
	snmpIfCfg_t	*ifc;

	snmp->cfg_ifCnt = 0;
	
	bzero(snmp,sizeof(snmpCfg_t));
	for (i=0, elapp=at_interfaces,ifc=snmp->cfg_ifCfg; 
		 i<IF_TOTAL_MAX; i++, elapp++, ifc++) {
		if (elapp->ifState != LAP_OFFLINE) {
			snmp->cfg_ifCnt++;
			strncpy(ifc->ifc_name,elapp->ifName, sizeof(ifc->ifc_name));
			ifc->ifc_aarpSize = getAarpTableSize(i);
			ifc->ifc_addrSize = getPhysAddrSize(i);
			switch (elapp->aa_ifp->if_type) {
				case IFT_ETHER:
					ifc->ifc_type = SNMP_TYPE_ETHER2;
					break;
				case IFT_ISO88025: /* token ring */
					ifc->ifc_type = SNMP_TYPE_TOKEN;
					break;
				case IFT_FDDI:
				default:
					ifc->ifc_type = SNMP_TYPE_OTHER;
					break;
			}
			ifc->ifc_start 	= elapp->ifThisCableStart;
			ifc->ifc_end	= elapp->ifThisCableEnd;
			ifc->ifc_ddpAddr= elapp->ifThisNode;
			ifc->ifc_status	= elapp->ifState == LAP_ONLINE ? 1 : 2;
			ifc->ifc_zoneName.len = 0;
			if (elapp->ifZoneName.len != 0) {
				ifc->ifc_zoneName = elapp->ifZoneName;
			}
			else if (elapp->ifDefZone) {
				ifc->ifc_zoneName = ZT_table[elapp->ifDefZone-1].Zone;
			}
			else	/* temp, debug only */
				ifc->ifc_zoneName = ZT_table[0].Zone;
			if (ROUTING_MODE) {
				if (elapp->ifFlags & RTR_SEED_PORT) {
					ifc->ifc_netCfg  = SNMP_CFG_CONFIGURED;
					ifc->ifc_zoneCfg = SNMP_CFG_CONFIGURED;
				}
				else {
					ifc->ifc_netCfg  = SNMP_CFG_GARNERED;
					ifc->ifc_zoneCfg = SNMP_CFG_GARNERED;
				}
			}
			else  { 	/* single-port mode */
				if (elapp->ifRouterState == ROUTER_AROUND) {
					ifc->ifc_netCfg = SNMP_CFG_GARNERED;
				}
				else {
					ifc->ifc_netCfg = SNMP_CFG_GUESSED;
					ifc->ifc_zoneCfg = SNMP_CFG_UNCONFIG;
				}
			}
		}
	} 
	snmp->cfg_flags = at_state.flags;

		
	return(0);
}	

int at_reg_mcast(ifID, data)
     at_ifaddr_t *ifID;
     caddr_t data;
{
	struct ifnet *nddp = ifID->aa_ifp;
	struct sockaddr sa;

	if (*(int *)data) {
		if (!nddp) {
			dPrintf(D_M_PAT, D_L_STARTUP, ("pat_mcast: BAD ndpp\n"));
			return(-1);
		}

		if (elap_trackMcast(ifID, MCAST_TRACK_ADD, data) == 1)
			return(0);

		/* this is for ether_output */
		sa.sa_family = AF_UNSPEC;
		sa.sa_len = 2 + sizeof(struct etalk_addr);
		bcopy (data, &sa.sa_data[0], sizeof(struct etalk_addr));

		dPrintf(D_M_PAT, D_L_STARTUP,
			("pat_mcast: adding multicast %08x%04x ifID:0x%x\n",
			 *(unsigned*)data, (*(unsigned *)(data+2))&0x0000ffff, 
			 (unsigned)ifID));

		if (if_addmulti(nddp, &sa, 0))
			return -1;
	}
	return 0;

}

int at_unreg_mcast(ifID, data)
     at_ifaddr_t *ifID;
     caddr_t data;
{
	struct ifnet *nddp = ifID->aa_ifp;
	struct sockaddr sa;

	if (*(int *)data) {
		if (!nddp) {
			dPrintf(D_M_PAT, D_L_STARTUP, ("pat_mcast: BAD ndpp\n"));
			return(-1);
		}

		elap_trackMcast(ifID, MCAST_TRACK_DELETE, data);

		/* this is for ether_output */
		sa.sa_family = AF_UNSPEC;
		sa.sa_len = 2 + sizeof(struct etalk_addr);
		bcopy (data, &sa.sa_data[0], sizeof(struct etalk_addr));

		dPrintf(D_M_PAT, D_L_STARTUP,
			("pat_mcast: deleting multicast %08x%04x ifID:0x%x\n",
			 *(unsigned*)data, (*(unsigned *)(data+2))&0x0000ffff, 
			 (unsigned)ifID));
		bzero(data, sizeof(struct etalk_addr));

		if (if_delmulti(nddp, &sa))
			return -1;
	}
	return 0;
}
#ifdef NOT_YET
/* *** at_reg_mcast() and at_unreg_mcast() should be replaced as soon as the
       new code to allow an AF_LINK address family multicast to be (un)registered
       using the SIOCADDMULTI / SIOCDELMULTI ioctls has been completed.

       The issue is that the "struct sockaddr_dl" needed for the AF_LINK does not 
       fit in the "struct ifreq" that is used for these ioctls, and we do not want
       Blue/Classic, which currently uses AF_UNSPEC, to use a different address 
       family multicast address than Mac OS X uses.
   *** */

int at_reg_mcast(ifID, data)
     at_ifaddr_t *ifID;
     caddr_t data;
{
	struct ifnet *nddp = ifID->aa_ifp;
	struct sockaddr_dl sdl;

	if (*(int *)data) {
		if (!nddp) {
			dPrintf(D_M_PAT, D_L_STARTUP, ("pat_mcast: BAD ndpp\n"));
			return(-1);
		}
		if (elap_trackMcast(ifID, MCAST_TRACK_ADD, data) == 1)
			return(0);

		sdl.sdl_len = sizeof(struct sockaddr_dl);
		sdl.sdl_family = AF_LINK;
		sdl.sdl_index = 0;
		sdl.sdl_type = nddp->if_type;
		sdl.sdl_alen = nddp->if_addrlen;
		sdl.sdl_slen = 0;
		sdl.sdl_nlen = sprintf(sdl.sdl_data, "%s%d", 
				       nddp->if_name , nddp->if_unit);
		bcopy(data, LLADDR(&sdl), sdl.sdl_alen);

		dPrintf(D_M_PAT, D_L_STARTUP,
			("pat_mcast: adding multicast %08x%04x ifID:0x%x\n",
			 *(unsigned*)data, (*(unsigned *)(data+2))&0x0000ffff, 
			 (unsigned)ifID));

		if (if_addmulti(nddp, (struct sockaddr *)&sdl, 0))
			return -1;
	}

	return 0;
}

int at_unreg_mcast(ifID, data)
     at_ifaddr_t *ifID;
     caddr_t data;
{
	struct ifnet *nddp = ifID->aa_ifp;
	struct sockaddr_dl sdl;

	if (*(int *)data) {
		if (!nddp) {
			dPrintf(D_M_PAT, D_L_STARTUP, ("pat_mcast: BAD ndpp\n"));
			return(-1);
		}

		elap_trackMcast(ifID, MCAST_TRACK_DELETE, data);

		sdl.sdl_len = sizeof(struct sockaddr_dl);
		sdl.sdl_family = AF_LINK;
		sdl.sdl_index = 0;
		sdl.sdl_type = nddp->if_type;
		sdl.sdl_alen = nddp->if_addrlen;
		sdl.sdl_slen = 0;
		sdl.sdl_nlen = sprintf(sdl.sdl_data, "%s%d", 
				       nddp->if_name , nddp->if_unit);

		dPrintf(D_M_PAT, D_L_STARTUP,
			("pat_mcast: deleting multicast %08x%04x ifID:0x%x\n",
			 *(unsigned*)data, (*(unsigned *)(data+2))&0x0000ffff, 
			 (unsigned)ifID));
		bzero(data, ETHERNET_ADDR_LEN);	

		if (if_delmulti(nddp, (struct sockaddr *)&sdl))
			return(-1);
	}

	return 0;
}

#endif
