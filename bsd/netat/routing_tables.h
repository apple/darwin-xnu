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
/*
 *    This include file defines the RTMP table and ZIP table
 *    for the AppleTalk AIX router
 *
 *
 *  0.01	03/16/94	LD	Creation
 *  0.10	08/19/94	LD	merged	
 *
 */

#ifndef _NETAT_ROUTING_TABLES_H_
#define _NETAT_ROUTING_TABLES_H_
#include <sys/appleapiopts.h>
#ifdef PRIVATE

/* RTMP table entry state bitmap (EntryState) values */

#define RTE_STATE_UNUSED	0		/* this entry is not in used */
#define RTE_STATE_BAD		2		/* The route is almost ready to be removed */
#define RTE_STATE_SUSPECT	4		/* didn't received an update for route */
#define RTE_STATE_GOOD		8		/* this route is 100% valid */
#define RTE_STATE_ZKNOWN	16		/* we know the zones for this entry */
#define RTE_STATE_UPDATED	32		/* set when updated from received rtmp table */
#define RTE_STATE_BKUP		64	/* for future use : AURP */
#define RTE_STATE_PERMANENT	128	/* This is a directly attached route */

#define PORT_ONLINE    		32	/* router port in forwarding state */
#define PORT_SEEDING		31	/* router port seeding	*/
#define PORT_ACTIVATING 	16	/* router port waiting for net infos */
#define PORT_ERR_NOZONE		6	/* router no zones for non seed port*/
#define PORT_ERR_BADRTMP	5	/* router problem bad rtmp version*/
#define PORT_ERR_STARTUP	4	/* router problem cable in start range*/
#define PORT_ERR_CABLER		3	/* router problem bad cable range*/
#define PORT_ERR_SEED		2	/* router startup seeding problem */
#define PORT_ONERROR		1	/* router port with generic problem*/
#define PORT_OFFLINE 		0	/* router port disabled/not ready */

#define ZT_MAX			1024	/* Don't allow more zones than that */
#define ZT_MIN			32	/* Minimum for a good behaviour*/
#define ZT_DEFAULT		512	/* Minimum for a good behaviour*/
#define RT_MAX			4096	/* Don't allow more entries than that */
#define RT_MIN			128	/* Minimum for a good behaviour*/
#define RT_DEFAULT		1024	/* Minimum for a good behaviour*/
#define ZT_BYTES		(ZT_MAX/8)	/* Bytes in Zone Bitmap */
#define ZT_MAXEDOUT		ZT_MAX+1	/* reached the entry limit.. */
#define RT_MIX_DEFAULT		2000	/* default for nbr of ppsec */


#define NOTIFY_N_DIST   31      /* Notify Neighbor distance (when shutdown or so) */

/* Useful macros to access the RTMP tuple fields */

#define TUPLENET(x) NET_VALUE(((at_rtmp_tuple *)(x))->at_rtmp_net)
#define TUPLEDIST(x)  ((((at_rtmp_tuple *)(x))->at_rtmp_data) & RTMP_DISTANCE)
#define TUPLERANGE(x) ((((at_rtmp_tuple *)(x))->at_rtmp_data) & RTMP_RANGE_FLAG)

#define CableStart  ifID->ifThisCableStart
#define CableStop  ifID->ifThisCableEnd

#define RTMP_IDLENGTH	4	/* RTMP packet Node header length */


#define RTMP_VERSION_NUMBER 0x82    	/* V2 only version of RTMP supported */

#define ERTR_SEED_CONFLICT  0x101   /* Conflict between port information and net
                                     * value received for the port (fatal for Rtr)
                                     */
#define ERTR_CABLE_CONFLICT 0x102   /* Conflict between port information and net
                                     * information received in a RTMP packet
                                     */

#define ERTR_RTMP_BAD_VERSION  0x103   /* We received a non phase-II RTMP packet
                                         * that's bad... We can't deal with it
                                         */

#define ERTR_CABLE_STARTUP  0x104   /* the cable range we're on happen to
									 * be in the startup range. Shouldn't
                                     */

#define ERTR_CABLE_NOZONE	0x105	/* We haven't found any zones for that port
									 * after all the timeout expired
									 */


/* RTMP table entry */

typedef struct rt_entry {

	struct rt_entry *left;		/* btree left pointer */
	struct rt_entry *right;		/* btree right pointer */

	at_net_al NetStop;		/* Last net # in the range, or network # if
					   non extended network */
	at_net_al NetStart;		/* Starting network number in the range, 0
					   non extended network */
	at_net_al NextIRNet;		/* Network number of next Internet Router */
	at_node NextIRNode;		/* Node ID of next Router */
	u_char ZoneBitMap[ZT_BYTES];	/* One bit per Zone defined for this entry */
	u_char NetDist;			/* Distance in hops of the destination net */
	u_char NetPort;			/* Physical port number to forward to */
	u_char EntryState;		/* State of the entry bitmap field */
	u_char RTMPFlag;
	u_char AURPFlag;

} RT_entry;

	
/* ZIP Table entry */

typedef struct {

	u_short ZoneCount;		/* Count of reference to zone entry */
	at_nvestr_t Zone;		/* zone name as a Network Visible Entity */

} ZT_entry;

/* for zone retrieval to user space only */
typedef struct {
	unsigned short 	entryno;	/* zone table entry number (1st = 0) */
	ZT_entry	zt;		/* the zone table entry */
} ZT_entryno;

#ifdef KERNEL_PRIVATE

/* Macros for Routing table B-tree easy access */

#define RT_DELETE(NetStop, NetStart) {\
    RT_entry *found; \
    if ((found = rt_bdelete(NetStop, NetStart))) { \
        memset(found, '\0', sizeof(RT_entry)); \
        found->right = RT_table_freelist; \
        RT_table_freelist  = found; \
    } \
}

/* Set/Reset and test the All zones known bit in for the entry field */

#define RT_ALL_ZONES_KNOWN(entry)  	((entry)->EntryState & RTE_STATE_ZKNOWN)
#define RT_SET_ZONE_KNOWN(entry)  	((entry)->EntryState |= RTE_STATE_ZKNOWN)
#define RT_CLR_ZONE_KNOWN(entry)  	((entry)->EntryState ^= RTE_STATE_ZKNOWN)

/*
 * check if a zone number is in a given zone map
 */
#define ZT_ISIN_ZMAP(znum, zmap) ((zmap)[(znum-1) >> 3] & 0x80 >> (znum-1) % 8)

/* remove a zone from the zone bitmap, and check if the zone
 * is still in use by someone else.
 */

#define ZT_CLR_ZMAP(num, zmap) {					\
	if ((zmap)[(num-1) >> 3] & 0x80 >> (num-1) % 8) {	\
		(zmap)[(num-1) >> 3] ^= 0x80 >> (num-1) % 8;	\
		ZT_table[(num-1)].ZoneCount-- ;				\
	}												\
}

/* set a bit in an entry bit map */

#define ZT_SET_ZMAP(num, zmap) {						\
	if (!zmap[(num-1) >> 3] & 0x80 >> (num-1) % 8) {	\
		zmap[(num-1) >> 3] |= 0x80 >> (num-1) % 8;		\
		ZT_table[(num-1)].ZoneCount++ ;					\
	}													\
}

extern int regDefaultZone(at_ifaddr_t *);
extern int zonename_equal(at_nvestr_t *, at_nvestr_t *);
	  
extern RT_entry *RT_table_freelist;
extern RT_entry RT_table_start;
extern RT_entry *RT_table;
extern RT_entry *rt_binsert (RT_entry *);
extern RT_entry *rt_insert( at_net_al NStop, at_net_al NStart, at_net_al NxNet,
     at_node NxNode, u_char NtDist, u_char NtPort, u_char EntS);
extern RT_entry *rt_bdelete (at_net_al NetStop, at_net_al NetStart);
extern RT_entry *rt_blookup(int);
extern RT_entry *rt_getNextRoute(int);

extern ZT_entry *ZT_table;
extern short	RT_maxentry;
extern short	ZT_maxentry;

extern int RouterMix;

extern int zt_add_zone(char *, short);
extern int zt_add_zonename(at_nvestr_t *);
extern int zt_ent_zindex(u_char *);
extern ZT_entryno *zt_getNextZone(int); 
extern void zt_remove_zones(u_char *);
extern void zt_set_zmap(u_short, unsigned char *);
extern void rtmp_router_input(gbuf_t *, at_ifaddr_t *);
void trackrouter(at_ifaddr_t *, unsigned short, unsigned char);
int zt_find_zname(at_nvestr_t *);
struct at_nvestr *getRTRLocalZone(struct zone_usage *);
int zt_ent_zcount(RT_entry *);
int zt_get_zmcast(at_ifaddr_t *, at_nvestr_t *, char *);

void getRtmpTable(RT_entry *, int, int	c);
void getZipTable(ZT_entry *, int, int	c);
int getZipTableSize(void);

int rt_table_init(void );
void getIfUsage( int, at_ifnames_t *);


#endif /* KERNEL_PRIVATE */

#endif /* PRIVATE */
#endif /* _NETAT_ROUTING_TABLES_H_ */
