/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
 *	Copyright (c) 1998 Apple Computer, Inc. 
 */

#ifndef _NETAT_AT_VAR_H_
#define _NETAT_AT_VAR_H_

#include <sys/appleapiopts.h>
#ifdef __APPLE_API_OBSOLETE
#include <sys/queue.h>

/* at_var.h */

/* at_var.h contains definitions formerly found in: at/at_lap.h & at/elap.h */

/* multicast tracking */
#define MAX_MCASTS 25   	/* #multicast addrs tracked per i/f */
#define MCAST_TRACK_ADD		1
#define MCAST_TRACK_DELETE	2
#define MCAST_TRACK_CHECK	3

/* maximum number of I/F's allowed */
#define IF_TOTAL_MAX	17	/* max count of any combination of I/F's */
				/* 17 == (1+(4*4)); 9 and 13 would also be
				   reasonable values */

#define FDDI_OR_TOKENRING(i) ((i == IFT_FDDI) || (i == IFT_ISO88025))
#define ETHERNET_ADDR_LEN 6
#define IFNAMESIZ 16
typedef struct etalk_addr {
	u_char 		etalk_addr_octet[ETHERNET_ADDR_LEN];	
} etalk_addr_t;
typedef char if_name_t[IFNAMESIZ];
typedef struct at_ifname_list {
	if_name_t at_if[IF_TOTAL_MAX];
} at_ifnames_t;

typedef struct at_if_statstics {
	u_long	fwdBytes;		/* bytes received & forwarded */
	u_long	fwdPkts;		/* pkts  received & forwarded */
	u_long	droppedBytes;		/* bytes received & dropped */
	u_long	droppedPkts;		/* pkts  received & dropped */ 
	u_long 	outBytes;		/* bytes sent */
	u_long	outPkts;		/* pkts  sent */
	u_long	routes;			/* count of routes in rtmptable */
} at_if_statistics_t;

typedef struct {
	u_int	unknown_mblks;	/* number of unknown streams msgs	*/
	u_int	rcv_bytes;  	/* number of data bytes received	*/
	u_int	rcv_packets;	/* number of packets received		*/
	u_int	xmit_bytes;	/* number of data bytes xmited		*/
	u_int	xmit_packets;	/* number of packets xmited		*/
} at_elap_stats_t;

typedef struct {
	char		ifr_name[IFNAMESIZ];
	u_int		flags;		/* misc. port flags, 
					   (ELAP_CFG_xxx on input 
					   ifFlags on output) */
	struct at_addr  node;		/* Our node number. */
	struct at_addr  router;		/* Our router. */
	u_short		netStart;	/* network start range */
	u_short		netEnd;		/* network ending range */
  	at_nvestr_t	zonename;
} at_if_cfg_t;

typedef struct {
	at_entity_t	name;
	at_inet_t	addr;		/* net and node are ignored, except in
					   multihoming mode where "addr" is used
					   to specify the interface. */
	u_char		ddptype;
	long		unique_nbp_id;
} at_nbp_reg_t;

typedef struct {
	char		ifr_name[IFNAMESIZ];
	at_nvestr_t	zonename;
} at_def_zone_t;

typedef struct zone_usage {
	int		zone_index;		/* index in local_zones */
	at_nvestr_t     zone_name;		/* the zone name & len */
	int		zone_home;		/* used only to set zones in
						   router mode */
	at_ifnames_t	zone_iflist;		/* list of interfaces for
						   this zone. */
	char		usage[IF_TOTAL_MAX];	/* I/F usage (set if
						   I/F in this zone) */
} zone_usage_t;

typedef struct {
	short multihome;
	short rtmp_table_sz;
	short zone_table_sz;
	short router_mix;
} at_router_params_t;


typedef struct at_kern_err {
	int		error;		/* kernel error # (KE_xxx) */
	int		port1;
	int		port2;
	char	name1[IFNAMESIZ];
	char	name2[IFNAMESIZ];
	u_short net;				
	u_char	node;
	u_short netr1b, netr1e;		/* net range 1 begin & end */
	u_short netr2b, netr2e;		/* net range 2 begin & end */
	u_char	rtmp_id;
} at_kern_err_t;

#define KE_CONF_RANGE 			1
#define KE_CONF_SEED_RNG 		2
#define KE_CONF_SEED1			3
#define KE_CONF_SEED_NODE		4
#define KE_NO_ZONES_FOUND		5
#define KE_NO_SEED			6
#define KE_INVAL_RANGE			7
#define KE_SEED_STARTUP			8	
#define KE_BAD_VER			9
#define KE_RTMP_OVERFLOW		10
#define KE_ZIP_OVERFLOW			11

#ifdef KERNEL_PRIVATE
/*
 * Interface address, AppleTalk version.  One of these structures
 * is allocated for each AppleTalk address on an interface.
 *
 * The ifaddr structure contains the protocol-independent part
 * of the structure and is assumed to be first, as it is in
 * "struct in_ifaddr", defined in bsd/netinet/in_var.h.
 */
typedef struct at_ifaddr {
	struct ifaddr	aa_ifa;
#define 		aa_ifp		aa_ifa.ifa_ifp
#define			aa_flags	aa_ifa.ifa_flags

	TAILQ_ENTRY(at_ifaddr) aa_link; /* tailq macro glue */
	int			at_was_attached; /* 1=attached, 0=detached */

	/* from pat_unit_t */
	unsigned char 	mcast[MAX_MCASTS];
        char  		xaddr[ETHERNET_ADDR_LEN];

	/* from elap_specifics_t */
	at_elap_stats_t	stats;

	/* The DDP sets these values: */
	u_char		ifState; 	/* State of the interface LAP_* */
	u_short		ifThisCableStart;
	u_short		ifThisCableEnd;
	struct	at_addr ifARouter;
	u_char		ifRouterState;
	u_int		ifFlags;	/* Flags, see AT_IFF_*  */
	struct sockaddr_at ifNodeAddress;
#define 		ifThisNode ifNodeAddress.sat_addr
				/* AppleTalk node ID is ifNodeAddress.sat_addr*/

	/* for use by ZIP */
	u_char		ifNumRetries;
	u_char		ifGNIScheduled;	/* to keep getnetinfo from being scheduled more than once */
	at_nvestr_t	ifZoneName;

	/* Added for routing support */
	int		ifPort;		/* the unique ddp logical port 
					   number, also index into
					   at_interfaces[] and ifID_table[] */
	char		ifName[IFNAMESIZ]; 
  					/* added to support LAP_IOC_GET_IFID */
	u_short		ifDefZone;	/*  Default Zone index in ZoneTable; used
					    only in routing/multihome modes to be
					    able to answer a ZIP GetNetInfo request */
	char		ifZipNeedQueries;
					/* ZIP/RTMP Query flag */
	char		ifRoutingState;	/* Port (as a router) state */
	at_if_statistics_t	
			ifStatistics;	/* statistics */
	/* end of elap_if structure */

	u_short		flags;		/* port specific flags */
	struct etalk_addr 	ZoneMcastAddr; 	
					/* zone multicast addr */
	struct etalk_addr	cable_multicast_addr;	
					/* AppleTalk broadcast addr */
	
	struct	at_addr	initial_addr;	/* temporary value used during startup */
  	at_nvestr_t	startup_zone;
	int		startup_error,  /* to get error code  back from
					   ZIPwakeup() / AARPwakeup() */
		 	startup_inprogress; /* to decide whether it's the
					   middle of an elap_online operation */

} at_ifaddr_t;
#endif /* KERNEL_PRIVATE */

#define	LAP_OFFLINE		0	/* LAP_OFFLINE MUST be 0 */	
#define	LAP_ONLINE		1
#define	LAP_ONLINE_FOR_ZIP	2
#define	LAP_ONLINE_ZONELESS	3	/* for non-home router ports */

#define	NO_ROUTER	1	/* there's no router around	*/
#define	ROUTER_WARNING	2	/* there's a router around that */
				/* we are ignoring, warning has */
				/* been issued to the user	*/
#define	ROUTER_AROUND	3	/* A router is around and we've */
				/* noted its presence		*/
#define ROUTER_UPDATED  4	/* for mh tracking of routers. Value decremented
				   with rtmp aging timer, a value of 4 allows a 
				   minimum of 40 secs to laps before we decide
				   to revert to cable multicasts */
              
/* AppleTalk IOCTLs */

              
#define AIOCSTOPATALK	_IOWR('a',  1, int)		/* stop AppleTalk */
#define AIOCGETIFCFG	_IOWR('a', 2, at_if_cfg_t)	/* get AT interface cfg */
#define AIOCNBPREG	_IOWR('a', 3, at_nbp_reg_t)	/* NBP register */
#define AIOCNBPREMOVE	_IOW('a', 4, at_nbp_reg_t)	/* NBP remove */
#define AIOCGETSTATE	_IOR('a', 5, at_state_t)	/* get AT global state */
#define AIOCSETDEFZONE	_IOW('a', 6, at_def_zone_t)
	/* in single-port, router, and multihome modes, set default zone */
#define AIOCSETROUTER	_IOW('a', 7, at_router_params_t)
#define AIOCGETROUTER	_IOR('a', 8, at_router_params_t)
#define AIOCSIFADDR	_IOW('a', 9, at_if_cfg_t)	/* init AT interface */
#define AIOCSTARTROUTER _IOR('a',10, at_kern_err_t)	/* start AT routing */
#define AIOCREGLOCALZN  _IOW('a',11, at_nvestr_t)
	/* in single-port mode, register local zone in kernel table for 
	   future use in error checking NBP registration */
#define AIOCSETZNUSAGE  _IOW('a',12, zone_usage_t)
	/* in router mode, set up each zone for interfaces being seeded */
#define AIOCGETZNUSAGE  _IOWR('a',13, zone_usage_t)
	/* in router and multihome modes, given a zone index, report zone name
	   and interfaces corresponding to that zone */

/* values for ifFlags */
#define LAP_STATE_MASK		       0xf	/* low order bits used to report
						   IF state, by AIOCGETIFCFG */
#define AT_IFF_DEFAULT		   0x40000
#define AT_IFF_AURP		   0x20000
#define RTR_NXNET_PORT  	0x10000000  /* Non Extended net port */
#define RTR_XNET_PORT   	0x20000000  /* Extended net port */
#define RTR_SEED_PORT   	0x40000000  /* Seed port require config net values*/

/* elap_cfg 'flags' defines */
#define ELAP_CFG_ZONELESS   0x01       /* true if we shouldn't set a zone
					  (to avoid generating a zip_getnetinfo
					  when routing) */
#define ELAP_CFG_HOME	    0x02	/* designate home port (one allowed) */
#define ELAP_CFG_SEED	    0x08	/* set if it's a seed port */

#ifdef KERNEL_PRIVATE
extern TAILQ_HEAD(at_ifQueueHd, at_ifaddr) at_ifQueueHd;

int at_control(struct socket *, u_long, caddr_t, struct ifnet *);
int ddp_usrreq(struct socket *, int, struct mbuf *, struct mbuf *, 
		    struct mbuf *);
int ddp_ctloutput(struct socket *, struct sockopt *);
void ddp_init(void);
void ddp_slowtimo(void);
#endif /* KERNEL_PRIVATE */

/*
 * Define AppleTalk event subclass and specific AppleTalk events.
 */

#define KEV_ATALK_SUBCLASS 5

#define KEV_ATALK_ENABLED				1	/* AppleTalk enabled from user space - node/net set and valid */
#define KEV_ATALK_DISABLED				2	/* AppleTalk disabled from user space */
#define KEV_ATALK_ZONEUPDATED			3	/* Zone for this node set/changed */
#define KEV_ATALK_ROUTERUP				4	/* Seed router found with valid cable range */
#define KEV_ATALK_ROUTERUP_INVALID		5	/* Seed router found with invalid cable range */
#define KEV_ATALK_ROUTERDOWN			6	/* Seed router down */
#define KEV_ATALK_ZONELISTCHANGED		7	/* Zone list changed by router */

struct kev_atalk_data {
	struct	net_event_data	link_data;
	union {
		struct	at_addr		address;
		at_nvestr_t			zone;
	} node_data;
};

#ifdef KERNEL_PRIVATE

void atalk_post_msg(struct ifnet *ifp, u_long event_code, struct at_addr *address, at_nvestr_t *zone);
void aarp_sched_probe(void *);
void atalk_lock(void);
void atalk_unlock(void);
void appletalk_hack_start(void);
void ddp_input(gbuf_t *, at_ifaddr_t *);
struct etalk_addr;
void ddp_glean(gbuf_t *, at_ifaddr_t  *, struct etalk_addr  *);

int pat_output(at_ifaddr_t *, struct mbuf *, unsigned char *, int);

void ep_input(gbuf_t *, at_ifaddr_t *);
void zip_router_input(gbuf_t *, at_ifaddr_t *);
void nbp_input(gbuf_t *, at_ifaddr_t *);
void sip_input(gbuf_t *, at_ifaddr_t *);

void ioc_ack(int, gbuf_t *, gref_t *);
int ddp_adjmsg(gbuf_t *, int );
gbuf_t *ddp_growmsg(gbuf_t  *, int );

struct proc;
int atalk_openref(gref_t *, int *, struct proc *);

struct fileglob;
int atalk_closeref(struct fileglob *, gref_t **);

int _ATputmsg(int, strbuf_t *, strbuf_t *, int , int *, void *);
int _ATgetmsg(int, strbuf_t *, strbuf_t *, int *, int *, void *);
int _ATsocket(int, int *, void *);

void ddp_start(void);

typedef void (*ddp_handler_func)(gbuf_t *, at_ifaddr_t *);
void add_ddp_handler(u_char, ddp_handler_func);
void init_ddp_handler(void);

int  elap_wput(gref_t *gref, gbuf_t *m);
int at_ioctl(struct atpcb *, u_long, caddr_t, int );

extern void at_purgeaddrs(struct ifnet *);

#endif /* KERNEL_PRIVATE */
#endif /* __APPLE_API_OBSOLETE */
#endif /* _NETAT_AT_VAR_H_ */
