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
/* 	Copyright (c) 1993 NeXT Computer, Inc.  All rights reserved. 
 *
 * tokensr.h - Token-ring IEEE 802.5 source routing utility functions.
 *
 *	We currently make these functions static inlines.  These should
 *	be considered for movement to a library and made public (after
 *	sanitizing API).
 *
 * HISTORY
 * 
 * 22-Jul-94 John Immordino (jimmord) at NeXT
 *	Converted static array of source routes to a hash table.
 * 	Loosely coupled hash table entries to arp table entries, ie.
 * 	when hash table is full, delete the first entry for which there
 * 	is no arp entry before inserting the next source route.
 *
 * 26-Apr-94 John Immordino (jimmord) at NeXT
 * 	Cleaned up.  Fixed byte-swap problems, converted all addresses to
 *	character arrays, etc.
 *
 * 07-Apr-93 Joel Greenblatt at NeXT 
 *	Created
 *
 */

#ifdef DRIVER_PRIVATE

#ifndef _TOKENSR_
#define _TOKENSR_

#include <sys/socket.h>
#include <net/tokendefs.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>	
#include <netinet/if_ether.h>	
#include <objc/hashtable.h>	/* Not an Obj-C header */

/*
 * Virtual driver parameters
 * Used by if_vtrXX modules
 */
typedef	struct {
	int vunit;
	int vflags;
	int vmtu;
	int vtokpri;
} vparms_t;


/*
 * Source routing table entry
 * Note: ipAddr must be the first element in order for our hash table
 * code to work properly.
 */
typedef struct	{
    unsigned long	ipAddr;		/* IP address of this entry - */
    					/* needed for our temporary   */
					/* arp table lookup scheme    */
    sroute_t		ri;		/* routing information field  */
} srtable_t;


/*
 * Encoded source-routing broadcast type (used as parameter to
 * source routing routines).
 */
typedef enum {
	SRB_OFF, 		/* no source-route broadcast */
	SRB_AR,			/* all-routes broadcast */
	SRB_SR,			/* single-route broadcast */
	SRB_INVALID		/* invalid entry */
} srbcast_t;

/* 
 * ARP code taken from bsd/netinet/if_ether.c.  Need this in order
 * to perform lookups of IP addresses to determine which source route
 * entry to remove from the table.  The first source route entry without
 * a corresponding ARP entry will be removed.
 */
#ifdef GATEWAY
#define	ARPTAB_BSIZ	16		/* bucket size */
#define	ARPTAB_NB	37		/* number of buckets */
#else
#define	ARPTAB_BSIZ	9		/* bucket size */
#define	ARPTAB_NB	19		/* number of buckets */
#endif

extern struct arptab arptab[];

#define	ARPTAB_HASH(a) \
	((u_long)(a) % ARPTAB_NB)

/*
 *  Change to permit multiple heterogenous interfaces to co-exist.
 */
#define	ARPTAB_LOOK(at,addr,ifp) { \
	register n; \
	at = &arptab[ARPTAB_HASH(addr) * ARPTAB_BSIZ]; \
	for (n = 0 ; n < ARPTAB_BSIZ ; n++,at++) \
		if (at->at_iaddr.s_addr == addr && \
		    (!(ifp) || at->at_if == (ifp))) \
			break; \
	if (n >= ARPTAB_BSIZ) \
		at = 0; \
}


/*
 * Initialize callers source routing table.
 */
static __inline__
void init_src_routing(NXHashTable **sourceRouteTable)
{
    extern NXHashTablePrototype SRTablePrototype;
    *sourceRouteTable = NXCreateHashTable(SRTablePrototype, 0, NULL);
} 

/*
 * Search for a source route (given a destination address).
 */
static __inline__
sroute_t *find_sr(NXHashTable *sourceRouteTable, unsigned long idst)
{
    srtable_t *sourceRouteEntry = NXHashGet(sourceRouteTable, 
    	(const void *)&idst);
    if (sourceRouteEntry) {
    	return &sourceRouteEntry->ri;
    }
    return NULL;
}

/*
 * Add an entry to the callers source routing table.
 */
static __inline__
void add_sr(netif_t netif, NXHashTable *sourceRouteTable, unsigned long ipAddr,
	sroute_t *rip, unsigned long srLimit)
{
    srtable_t		*sourceRouteEntry;
    struct ifnet 	*ifp = (struct ifnet *)netif;
    
    if ((rip->rc.len > 18)|| (rip->rc.len < 2) || (rip->rc.len & 1))
	return;  

    /*
     * See if the entry is already in the table
     */
    sourceRouteEntry = NXHashGet(sourceRouteTable,&ipAddr);
    if (sourceRouteEntry) {
	bcopy(rip, &sourceRouteEntry->ri, rip->rc.len);
	sourceRouteEntry->ri.rc.bcast = 0;  		/* make non-bcast */
	sourceRouteEntry->ri.rc.dir = ~sourceRouteEntry->ri.rc.dir;   
	return;   
    }

    /*
     * See if there's room in the table for another entry.
     */
    if (NXCountHashTable(sourceRouteTable) >= srLimit) {
	BOOL		dumpedOne = NO;	
	NXHashState	state = NXInitHashState(sourceRouteTable);
	
	/*
	 * Need to delete an entry.
	 */
	while (NXNextHashState(sourceRouteTable, &state,
		(void **)&sourceRouteEntry)) {
	    
	    struct arptab *at;
	    
	    /*
	     * Look for an entry without a corresponding entry in the 
	     * arp table.
	     */
	    ARPTAB_LOOK(at, sourceRouteEntry->ipAddr, ifp);
	    if (at == NULL) {
		/*
		 * Found one - try to remove it 
		 */
	    	sourceRouteEntry = 
		    NXHashRemove(sourceRouteTable,
			(const void *)&sourceRouteEntry->ipAddr);
		if (sourceRouteEntry) {
		    kfree(sourceRouteEntry,sizeof(srtable_t));
		    dumpedOne = YES;
		    break;
		}
	    }
	}
	if (dumpedOne == NO) {
	    printf("add_sr: source route table overflow\n");
	    return;
	}
    }
    
    sourceRouteEntry = (srtable_t *)kalloc(sizeof(srtable_t));

    sourceRouteEntry->ipAddr = ipAddr;
    bcopy(rip, &sourceRouteEntry->ri, rip->rc.len);
    sourceRouteEntry->ri.rc.bcast = 0;  		/* make non-bcast */
    sourceRouteEntry->ri.rc.dir = ~sourceRouteEntry->ri.rc.dir;   
    
    sourceRouteEntry = 
	NXHashInsert(sourceRouteTable,(const void *)&sourceRouteEntry->ipAddr);
    if (sourceRouteEntry)	/* shouldn't happen */
    	kfree(sourceRouteEntry,sizeof(srtable_t));
} 

/* 
 * Find & return the source route to the callers address. 
 */
static __inline__
void get_src_route(NXHashTable *sourceRouteTable, unsigned long idst, 
    unsigned char *da, tokenHeader_t *th)
{
    sroute_t	*sourceRoute;

    if (da[0] & 0x80) 
    	return;				/* don't handle group addresses */
	
    /* 
     * Find source route in srtable and copy to caller's 
     * tokenHeader_t (or turn off sri bit).
     */ 
    sourceRoute = find_sr(sourceRouteTable, idst);
    if (sourceRoute) {
	bcopy(sourceRoute, &th->ri, sourceRoute->rc.len);
	th->sa[0] |= TR_RII;
    } 
    else
	th->sa[0] &= ~TR_RII;		/* turn off source routing bit */
} 

/* 
 * Save the source route in the callers MAC header. 
 */
static __inline__
void save_src_route(netif_t netif, NXHashTable *sourceRouteTable, 
    unsigned long ipAddr, tokenHeader_t *th, unsigned long srLimit)
{
    /* 
     * If frame has a routing field > 2 then save it (i.e. it's been
     * thru at least one bridge). 
     */
    if ((th->sa[0] & TR_RII) && (th->ri.rc.len > 2))
	add_sr(netif, sourceRouteTable, ipAddr, &th->ri, srLimit);
} 


/*
 * Returns length of the source routing field in callers MAC header.
 * Returns -1 if the header is invalid.
 */
static __inline__
int get_ri_len(tokenHeader_t *th)
{
    int		ri_len = 0;
    sroute_t 	*rif = (sroute_t *)&th->ri;

    if (th->sa[0] & 0x80) {
	ri_len = (int)rif->rc.len;
	if ((ri_len & 1) || (ri_len < 2) || (ri_len > 18)) {
	    ri_len = -1;
	}
    }
    return ri_len;
}

/*
 * Returns the length of an 802.5 MAC header (including routing field).
 */
static __inline__
int get_8025_hdr_len(tokenHeader_t *th)
{
    int ri_len;

    ri_len = get_ri_len(th);
    if (ri_len < 0) 
	return ri_len; // bad header

    return ri_len + MAC_HDR_MIN;
}

/*
 * Returns 1 if mac address is any type of broadcast, zero otherwise.
 */
static __inline__
int check_mac_bcast(tokenHeader_t *th)
{
    if (th->da[0] & 0x80)
	return 1; 		// group address (I/G bit)
    return 0; 
}

/*
 * Build a broadcast routing field in the callers MAC header.
 */
static __inline__
void make_sr_bcast(tokenHeader_t *th, srbcast_t type)
{
    if ((type == SRB_OFF) || (type >= SRB_INVALID)) {
	th->sa[0] &= ~TR_RII;   	
	return;
    }

    th->sa[0] |= TR_RII;	/* turn on rii bit to ind. src rtng field */	 

    /*
     * Build the routing control field for the requested
     * broadcast type.
     */
    if (type == SRB_AR)
	th->ri.rc.bcast = BI_AR_BCAST;
    else
	th->ri.rc.bcast = BI_SR_BCAST;

    th->ri.rc.len = 2;
    th->ri.rc.dir = 0;
    th->ri.rc.longf = LF_BCAST;
    th->ri.rc.rsrvd = 0;
}

/*
 * Make the callers MAC header a reply to sender.
 */
static __inline__
void make_mac_reply(tokenHeader_t *th)
{

    /*
     * Copy source address to destination address.  Turn off RII bit in
     * the destination address.
     */
    bcopy(th->sa, th->da, sizeof(th->da));
    th->da[0] &= ~TR_RII;
    
    /*
     * Convert the source routing field to a reply (flip direction
     * bit & turn off broadcast bits). 
     */
    if (th->sa[0] & TR_RII) {
	th->ri.rc.dir = ~th->ri.rc.dir;
	th->ri.rc.bcast = 0;
    }
}


#endif /* _TOKENSR_ */

#endif /* DRIVER_PRIVATE */
