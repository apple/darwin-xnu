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
 *	Copyright (c) 1998 Apple Computer, Inc. 
 */

/*	at.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/file.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/dlil.h>

#include <netat/appletalk.h>
#include <netat/sysglue.h>
#include <netat/at_pcb.h>
#include <netat/at_var.h>
#include <netat/ddp.h>
#include <netat/nbp.h>
#include <netat/routing_tables.h>
#include <netat/debug.h>

#include <sys/kern_event.h>

extern int at_ioctl(struct atpcb *, u_long, caddr_t, int fromKernel);
extern int routerStart(at_kern_err_t *);
extern void elap_offline(at_ifaddr_t *);
extern at_ifaddr_t *find_ifID(char *);
extern at_nvestr_t *getRTRLocalZone(zone_usage_t *);
extern int setLocalZones(at_nvestr_t *, int);

extern int xpatcnt;
extern at_ifaddr_t at_interfaces[];
extern at_ifaddr_t *ifID_home;
extern TAILQ_HEAD(name_registry, _nve_) name_registry;
extern int nve_lock;

struct  etalk_addr      etalk_multicast_addr = {
  {0x09, 0x00, 0x07, 0xff, 0xff, 0xff}};
struct  etalk_addr      ttalk_multicast_addr = {
  {0xC0, 0x00, 0x40, 0x00, 0x00, 0x00}};

/* called only in router mode */
static int set_zones(ifz)
	zone_usage_t *ifz;

/* 1. adds zone to table
   2. looks up each route entry from zone list
   3. sets zone bit in each route entry

   returns  0 if successful
	    errno if error occurred
*/
{
	int i;
	at_ifaddr_t *ifID;
	short zno;
	RT_entry *rte;

	zno = zt_add_zone(ifz->zone_name.str, ifz->zone_name.len);

	if (zno == ZT_MAXEDOUT) {
		dPrintf(D_M_ELAP, D_L_ERROR, ("set_zones: error: table full\n"));
		return(ENOSPC);
	}
	if (ifz->zone_home) {
		ifID_home->ifZoneName = ifz->zone_name;
		ifID_home->ifDefZone = zno;
	}

	for (i=0; i<IF_TOTAL_MAX; i++)  {
		if (ifz->zone_iflist.at_if[i][0]) {  
			if ((ifID = find_ifID(ifz->zone_iflist.at_if[i]))) {
				rte = rt_blookup(ifID->ifThisCableEnd);
				if (!rte) {
					dPrintf(D_M_ELAP, D_L_ERROR,
						("set_zones: error: can't find route\n"));
				} else {
					zt_set_zmap(zno, rte->ZoneBitMap); 

					/* if first zone for this I/F, 
					   make default */
					if (!ifID->ifDefZone)
						ifID->ifDefZone = zno;
				}
			}
		}
	}

	return(0);
} /* set_zones */

/*
  * Generic internet control operations (ioctl's).
  * ifp is 0 if not an interface-specific ioctl.
  */

int at_control(so, cmd, data, ifp)
     struct socket *so;
     u_long cmd;
     caddr_t data;
     struct ifnet *ifp;
{
	struct ifreq *ifr = (struct ifreq *)data;
	int pat_id = 0, error = 0;
	struct proc *p = current_proc();       
	at_ifaddr_t *ifID = 0;
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;

	if (cmd == 0x2000ff99) {
		/* *** this is a temporary hack to get at_send_to_dev() to
		   work with BSD-style sockets instead of the special purpose 
		   system calls, ATsocket() and ATioctl().
		   *** */
		if ((error = at_ioctl((struct atpcb *)so->so_pcb, cmd, data, 0))) {
		  if (((struct atpcb *)so->so_pcb)->proto != ATPROTO_LAP) {
		    ((struct atpcb *)so->so_pcb)->proto = ATPROTO_LAP;
		    error = at_ioctl((struct atpcb *)so->so_pcb, cmd, data, 0);
		  }
		}
		return(error);

		/* *** processing should be
		   return(EINVAL);
		   *** */
	}
        /*
	 * Find address for this interface, if it exists.
	 */
	if (ifp)
		for (pat_id = 0; pat_id < xpatcnt; pat_id++)
		  if (at_interfaces[pat_id].aa_ifp == ifp) {
			ifID = &at_interfaces[pat_id];
			break;
		  }
	
	switch (cmd) {

	case AIOCGETSTATE:
	  {
	  	at_state_t *global_state = (at_state_t *)data;

		*global_state = at_state;
		return(0);
		break;
	  }

	case AIOCGETIFCFG:
	  {
	  	at_if_cfg_t *cfgp = (at_if_cfg_t *)data;

		ifID = 0;
		if ((at_state.flags & AT_ST_STARTED) &&
		    ifID_home) {
			if (strlen(cfgp->ifr_name)) {
				TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
					if (!strncmp(ifID->ifName, cfgp->ifr_name, 
						     strlen(ifID->ifName)))
						break;
				}
			} else {
				ifID = ifID_home;
				strncpy(cfgp->ifr_name, ifID->ifName, 
					sizeof(ifID->ifName));
			}
			if  (ifID && ifID->ifState != LAP_OFFLINE) {
				cfgp->flags = ifID->ifFlags;
				/* put the IF state into the low order 
				   bits of flags */
				cfgp->flags |= (ifID->ifState & LAP_STATE_MASK);
				cfgp->node = ifID->ifThisNode;
				cfgp->router = ifID->ifARouter;
				cfgp->netStart = ifID->ifThisCableStart;
				cfgp->netEnd = ifID->ifThisCableEnd;
				cfgp->zonename = ifID->ifZoneName;
				return(0);
			} else
				return(EINVAL);
		} else
			return(ENOTREADY);
		break;
	  }

	case AIOCSETDEFZONE:
	  {
	  	at_def_zone_t *defzonep = (at_def_zone_t *)data;

		/* check for root access */
		if (error = suser(p->p_ucred, &p->p_acflag))
			return(EACCES);

		ifID = 0;
		if ((at_state.flags & AT_ST_STARTED) && ifID_home) {
			if (strlen(defzonep->ifr_name)) {
			    TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
				if (!strncmp(ifID->ifName, defzonep->ifr_name, 
					     strlen(ifID->ifName)))
				    break;
			    }
			} else {
				ifID = ifID_home;
				strncpy(defzonep->ifr_name, ifID->ifName, 
					sizeof(ifID->ifName));
			}

			/* In routing mode the default zone is only set for the 
			   default interface. */
			if (ROUTING_MODE && (ifID != ifID_home))
				return(EINVAL);

			if  (ifID && ifID->ifState != LAP_OFFLINE) {
				if (zonename_equal(&ifID->ifZoneName, 
						   &defzonep->zonename)) 
					return(0);
				else {
					/* check the zone name */
					if (MULTIPORT_MODE) {
					  short zno;
					  at_ifnames_t ifs_in_zone;

					  if (!(zno = zt_find_zname(&defzonep->zonename)))
					    return(EINVAL);

					  getIfUsage(zno-1, &ifs_in_zone);
					  if (!ifs_in_zone.at_if[ifID->ifPort]) 
					    return(EINVAL);
					  ifID->ifDefZone = zno+1;
					} else {
					  int i;
					  at_nvestr_t *zone;

					  for (i = 0, zone = getSPLocalZone(i); 
					       zone; 
					       i++, zone = getSPLocalZone(i)) {
					    if (zonename_equal(zone, 
							       &defzonep->zonename))
					      break;
					  }
					  if (!zone)
					    return(EINVAL);
					}
					ifID->ifZoneName = defzonep->zonename;
					(void)regDefaultZone(ifID);

					/* AppleTalk zone was changed. Send event with zone info. */
					atalk_post_msg(ifID->aa_ifp, KEV_ATALK_ZONEUPDATED, 0, &(ifID->ifZoneName));

					return(0);
				}
			} else
				return(EINVAL);
		} else
			return(ENOTREADY);
		break;
	  }

	case AIOCREGLOCALZN:
	  {
		at_nvestr_t *zone = (at_nvestr_t *)data;

		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home)
			return(ENOTREADY);

		if (MULTIPORT_MODE)
			return(EINVAL);

		return(setLocalZones(zone, zone->len));

		break;
	  }
	case AIOCSETZNUSAGE:
		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home)
			return(ENOTREADY);

		if (!ROUTING_MODE)
			return(EINVAL);

		return(set_zones((zone_usage_t *)data));

		break;

	case AIOCGETZNUSAGE:
		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home)
			return(ENOTREADY);

		if (!MULTIPORT_MODE)
			return(EINVAL);

		if (getRTRLocalZone((zone_usage_t *)data))
			return(0);
		else
			return(ENOENT);
		break;

	case AIOCNBPREG:
	  {
	  	at_nbp_reg_t *nbpP = (at_nbp_reg_t *)data;
		nve_entry_t nve;
		int error;

		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home)
			return(ENOTREADY);

		/* multihoming mode */
		if (MULTIHOME_MODE) {
			return(nbp_mh_reg(nbpP));
		}

		/* single port mode or router mode */
		if (nbp_fillin_nve(&nbpP->name, &nve) != 0) {
			/* bad tuple... */
			return(EINVAL);
		}

		/* In routing mode when the zone is specified, we need to 
		   find an interface on which the specified zone is seeded, so
		   that the zone multicast will be plausible. */
		if (ROUTING_MODE && !(DEFAULT_ZONE(&nve.zone))) {
		        /* find first segment (interface) which is seeded for 
			   this zone */
			int finished = FALSE;
			int zno;
			at_ifnames_t ifs_in_zone;
			if (!(zno = zt_find_zname(&nve.zone))) {
				return(EINVAL);
			}
			getIfUsage(zno-1, &ifs_in_zone);

			TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
				if (!ifs_in_zone.at_if[ifID->ifPort]) 
						/* zone doesn't match */
					continue;
				else {
					finished = TRUE;
					break;
				}
			}
			if (!finished)
				return(EINVAL);
		} else 
			ifID = ifID_home;

		nve.address.net = ifID->ifThisNode.s_net;
		nve.address.node = ifID->ifThisNode.s_node;
		nve.address.socket = nbpP->addr.socket;
		nve.ddptype = nbpP->ddptype;

		if (nbp_find_nve(&nve))
			return(EADDRNOTAVAIL);

		/* Normal case; no tuple found for this name, so insert
		 * this tuple in the registry and return ok response.
		 */
		ATDISABLE(nve_lock, NVE_LOCK);
		if ((error = nbp_new_nve_entry(&nve, ifID)) == 0) {
			nbpP->addr.net = ifID->ifThisNode.s_net;
			nbpP->addr.node = ifID->ifThisNode.s_node;
			nbpP->unique_nbp_id = nve.unique_nbp_id;
		}
		ATENABLE(nve_lock, NVE_LOCK);

		return(error);
		break;
	  }

	case AIOCNBPREMOVE:
	  {
	  	at_nbp_reg_t *nbpP = (at_nbp_reg_t *)data;
		nve_entry_t    *nve_entry, nve;

		if (!(at_state.flags & AT_ST_STARTED))
			return(ENOTREADY);

		/* delete by id */
		if (nbpP->unique_nbp_id) {
			ATDISABLE(nve_lock, NVE_LOCK);
			TAILQ_FOREACH(nve_entry, &name_registry, nve_link) {
				if (nve_entry->unique_nbp_id == nbpP->unique_nbp_id) {
					/* Found a match! */
					nbp_delete_entry(nve_entry);
					ATENABLE(nve_lock, NVE_LOCK);
					return(0);
				}
			}
			ATENABLE(nve_lock, NVE_LOCK);
			return(EADDRNOTAVAIL);
		}

		/* delete by entity */
		if (nbp_fillin_nve(&nbpP->name, &nve) != 0) {
			/* bad tuple... */
			return(EINVAL);
		}

		if (MULTIHOME_MODE && DEFAULT_ZONE(&nbpP->name.zone)) {
			/* if mhome & *, remove nve from all default zones */
			int found = FALSE;	/* if any found & deleted */

			TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
				nve.zone = ifID->ifZoneName;
				nve.zone_hash = nbp_strhash(&nve.zone);
				if ((nve_entry = nbp_find_nve(&nve)) == NULL) 
					continue;

				ATDISABLE(nve_lock, NVE_LOCK);
				nbp_delete_entry(nve_entry);
				ATENABLE(nve_lock, NVE_LOCK);
				found = TRUE;
			}
			if (found) 
				return(0);
			else
				return(EADDRNOTAVAIL);
		}

		if ((nve_entry = nbp_find_nve(&nve)) == NULL)
			/* Can't find the tuple we're looking for, send error*/
			return(EADDRNOTAVAIL);

		/* Normal case; tuple found for this name, so delete
		 * the entry from the registry and return ok response.
		 */
		ATDISABLE(nve_lock, NVE_LOCK);
		nbp_delete_entry(nve_entry);
		ATENABLE(nve_lock, NVE_LOCK);
		return(0);

		break;
	  }

	case AIOCSETROUTER:
	  {
	  	at_router_params_t *rt = (at_router_params_t *)data;

		/* check for root access */
		if (error = suser(p->p_ucred, &p->p_acflag))
			return(EACCES);

		/* when in routing/multihome mode the AIOCSETROUTER IOCTL 
		   is done first */
		if (at_state.flags & AT_ST_STARTED)
	    		return(EALREADY);

		/* Setup the routing & zip table size for the router */
		if (rt->rtmp_table_sz >= RT_MIN && rt->rtmp_table_sz <= RT_MAX)
                	RT_maxentry = rt->rtmp_table_sz;
		else
	                RT_maxentry = RT_DEFAULT;

		if (rt->zone_table_sz >= ZT_MIN && rt->zone_table_sz <= ZT_MAX)
			ZT_maxentry = rt->zone_table_sz;
		else
                	ZT_maxentry = ZT_DEFAULT;

		if (rt_table_init() == ENOBUFS)
			return(ENOBUFS);

		if (rt->router_mix)
			RouterMix = (int)rt->router_mix;
		else
			RouterMix = RT_MIX_DEFAULT;

		add_ddp_handler(RTMP_SOCKET, rtmp_router_input);

		if (rt->multihome)
                	at_state.flags |= AT_ST_MULTIHOME;
		else
			at_state.flags |= AT_ST_ROUTER;
		break;
	  }
	case AIOCSTARTROUTER:
	  {
	  	at_kern_err_t *keP = (at_kern_err_t *)data;

		/* check for root access */
		if (suser(p->p_ucred, &p->p_acflag))
			return(EACCES);

		if (!(at_state.flags & AT_ST_STARTED))
			return(ENOTREADY);

		bzero(keP, sizeof(at_kern_err_t));
		error = routerStart(keP);

		break;
	  }
	case AIOCGETROUTER:
	  {
	  	at_router_params_t *rt = (at_router_params_t *)data;

		if (!(at_state.flags & AT_ST_STARTED))
			return(ENOTREADY);

		rt->multihome = (MULTIHOME_MODE)? 1: 0;
		rt->rtmp_table_sz = RT_maxentry;
		rt->zone_table_sz = ZT_maxentry;
		rt->router_mix = RouterMix;

		break;
	  }
	case AIOCSTOPATALK:
	{
		int *count_only = (int *)data,
		    ret;

		/* check for root access */
		if (error = suser(p->p_ucred, &p->p_acflag))
			return(EACCES);

		ret = ddp_shutdown(*count_only);
		
		if (*count_only != 0) 
		{
			*count_only = ret;
			return(0);
		}
		else
		{
			if (ret == 0)
			{
				/* AppleTalk was successfully shut down. Send event. */
				atalk_post_msg(0, KEV_ATALK_DISABLED, 0, 0);
				return 0;
			}
			else
				return EBUSY;
		}

		break;
	}

	case SIOCSIFADDR:
		/* check for root access */
		if (error = suser(p->p_ucred, &p->p_acflag))
			error = EACCES;
		else if (ifID)
			error = EEXIST;
		else {
			int s;
			if (xpatcnt == 0) {
				at_state.flags |= AT_ST_STARTING;
				ddp_brt_init();
			}

			/* *** find an empty entry *** */
			ifID = &at_interfaces[xpatcnt];
			bzero((caddr_t)ifID, sizeof(at_ifaddr_t));
			strncpy(ifID->ifName, ifr->ifr_name, sizeof(ifID->ifName));

			ifID->aa_ifp = ifp;
			ifa = &ifID->aa_ifa;
			TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) 
				if ((sdl = (struct sockaddr_dl *)ifa->ifa_addr) &&
				      (sdl->sdl_family == AF_LINK)) {
				    bcopy(LLADDR(sdl), ifID->xaddr, sizeof(ifID->xaddr));
#ifdef APPLETALK_DEBUG
				    kprintf("SIOCSIFADDR: local enet address is %x.%x.%x.%x.%x.%x\n", 
					    ifID->xaddr[0], ifID->xaddr[1], 
					    ifID->xaddr[2], ifID->xaddr[3], 
					    ifID->xaddr[4], ifID->xaddr[5]);
#endif
				    break;
				  }

			/* attach the AppleTalk address to the ifnet structure */
			ifa = &ifID->aa_ifa;
			ifa->ifa_addr = (struct sockaddr *)&ifID->ifNodeAddress;
			ifID->ifNodeAddress.sat_len = sizeof(struct sockaddr_at);
			ifID->ifNodeAddress.sat_family =  AF_APPLETALK;
			/* the address itself will be filled in when ifThisNode
			   is set */
			s = splnet();
			TAILQ_INSERT_TAIL(&ifp->if_addrhead, ifa, ifa_link);
			splx(s);

			switch (ifp->if_type) {
			case IFT_ETHER:
				ether_attach_at(ifp, &ifID->at_dl_tag, 
						&ifID->aarp_dl_tag);
				error = 0;
				ifID->cable_multicast_addr = etalk_multicast_addr;

				xpatcnt++;
				break;
			case IFT_FDDI:
				ifID->cable_multicast_addr = etalk_multicast_addr;
				ddp_bit_reverse(&ifID->cable_multicast_addr);
				xpatcnt++;
				break;
			case IFT_ISO88025: /* token ring */	
				ifID->cable_multicast_addr = ttalk_multicast_addr;
				ddp_bit_reverse(&ifID->cable_multicast_addr);

				xpatcnt++;
				break;
			default:
				error = EINVAL;
			}
		}
	  break;

	/* complete the initialization started in SIOCSIFADDR */
	case AIOCSIFADDR:
	{
		at_if_cfg_t *cfgp = (at_if_cfg_t *)data;

		if (!(at_state.flags & AT_ST_STARTING))
			return(ENOTREADY);
 
		if (!(ifID = find_ifID(cfgp->ifr_name)))
			return(EINVAL);
		
		return(lap_online(ifID, cfgp));
		break;
	}

#ifdef NOT_YET
	/* *** this can't be added until AT can handle dynamic addition and
	       deletion of interfaces *** */
	case SIOCDIFADDR:
		/* check for root access */
		if (error = suser(p->p_ucred, &p->p_acflag))
			error = EACCES;
		else if (!ifID) 
			error = EINVAL;
		else
			elap_offline(ifID);
		break;
#endif

    case SIOCSETOT: {
        int				s;
        struct atpcb	*at_pcb, *clonedat_pcb;
        int				cloned_fd = *(int *)data;

        s = splnet();		/* XXX */
        at_pcb = sotoatpcb(so);
        
        /* let's make sure it's either -1 or a valid file descriptor */
        if (cloned_fd != -1) {
            struct socket	*cloned_so;
            struct file     *cloned_fp;
            error = getsock(p->p_fd, cloned_fd, &cloned_fp);
            if (error){
                splx(s);	/* XXX */
                break;
            }
            cloned_so = (struct socket *)cloned_fp->f_data;
            clonedat_pcb = sotoatpcb(cloned_so);
        } else {
            clonedat_pcb = NULL;
        }

        if (clonedat_pcb == NULL) {
            at_pcb->ddp_flags |= DDPFLG_STRIPHDR;
        } else {
            at_pcb->ddp_flags = clonedat_pcb->ddp_flags;
        }
        splx(s);		/* XXX */
        break;
    }
        
	default:
		if (ifp == 0 || ifp->if_ioctl == 0)
			return (EOPNOTSUPP);
		return dlil_ioctl(0, ifp, cmd, (caddr_t) data);
	}

	return(error);
}

/* From dlil_post_msg() */
void atalk_post_msg(struct ifnet *ifp, u_long event_code, struct at_addr *address, at_nvestr_t *zone) 
{
	struct kev_atalk_data  	at_event_data;
	struct kev_msg  		ev_msg;

	ev_msg.vendor_code    = KEV_VENDOR_APPLE;
	ev_msg.kev_class      = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass   = KEV_ATALK_SUBCLASS;
	ev_msg.event_code 	  = event_code;
	
	bzero(&at_event_data, sizeof(struct kev_atalk_data));
    
	if (ifp != 0) {
		strncpy(&at_event_data.link_data.if_name[0], ifp->if_name, IFNAMSIZ);
		at_event_data.link_data.if_family = ifp->if_family;
		at_event_data.link_data.if_unit   = (unsigned long) ifp->if_unit;
	}
	
	if (address != 0) {
		at_event_data.node_data.address = *address;
	}
	else if (zone != 0) {
		at_event_data.node_data.zone = *zone;
	}
    
	ev_msg.dv[0].data_length = sizeof(struct kev_atalk_data);
	ev_msg.dv[0].data_ptr    = &at_event_data;	
	ev_msg.dv[1].data_length = 0;
	
	kev_post_msg(&ev_msg);
}
