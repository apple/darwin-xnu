/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*----------------------------------------------------------------------------
 *
 *            RTMP & ZIP routing tables access routines
 *
 * This code implement b-tree search and manipulation of
 * of the RTMP routing table and ZIP zone table.
 *
 * The RTMP routing table is a data block divided in several routing
 * entries sorted during insertion in a b-tree form. We use a table and
 * not dynamically allocated entries because it allow us to scan the whole
 * table when RTMP packets are generated. The routing table entries are sorted
 * by there NetStop value (because non extended nets have a NetStart value of
 * zero. From any point in the tree, the left side contains Network ranges
 * smaller or equal to the current Node, and the right tree points to higher
 * values network ranges. 
 *
 *
 * 0.01 3/16/94 LD	Creation
 *    Modified for MP, 1996 by Tuyen Nguyen
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 *
 *----------------------------------------------------------------------------
 *
 *      Copyright (c) 1994, 1996, 1997, 1998 Apple Computer, Inc.
 */

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
#include <netat/rtmp.h>
#include <netat/at_pcb.h>
#include <netat/zip.h>
#include <netat/routing_tables.h>
#include <netat/at_snmp.h>
#include <netat/debug.h>

RT_entry *RT_table_freelist;	/* start of free entry list */
RT_entry RT_table_start;	/* start of the actual entry table */
RT_entry *RT_table;		/* the routing table */
ZT_entry *ZT_table;		/* the Zone Information Protocol table */
short	RT_maxentry;		/* Number of entry in RTMP table */
short	ZT_maxentry;		/* Number of entry in ZIP table */

char errstr[512];		/* used to display meaningfull router errors*/

extern at_ifaddr_t *ifID_table[];
extern at_ifaddr_t *ifID_home;
extern snmpStats_t	snmpStats;

short ErrorRTMPoverflow = 0;	/* flag if RTMP table is too small for this net */
short ErrorZIPoverflow  = 0;	/* flag if ZIP table is too small for this net */

	/* prototypes */
void getIfUsage( int, at_ifnames_t *);

/*
 * This a temporary function : just to display the router error 
 */

void RouterError(port, err_number)
short port, err_number;

{
	switch (err_number) {

	case ERTR_SEED_CONFLICT:
		dPrintf(D_M_RTMP, D_L_ERROR,
			 ("**** RTR Error on port# %d SEED_CONFLICT\n", port));
		break;
	
	case ERTR_CABLE_CONFLICT:
		dPrintf(D_M_RTMP, D_L_ERROR,
			("**** RTR Error on port# %d CABLE_CONFLICT\n", port));
		break;
	
	case ERTR_RTMP_BAD_VERSION:
		dPrintf(D_M_RTMP, D_L_ERROR,
			("**** RTR Error on port# %d RTMP_BAD_VERSION\n", port));
		break;

	case ERTR_CABLE_STARTUP:
		dPrintf(D_M_RTMP, D_L_ERROR,
			("**** RTR Error on port# %d RTMP_CABLE_STARTUP\n",
			 port));
		break;

	default:
		dPrintf(D_M_RTMP, D_L_ERROR,
			("**** RTR Error on port# %d WHAT IN THE WORLD IS THIS ONE? code=%d\n",
		 	port, err_number));
		break;
	}
	dPrintf(D_M_RTMP, D_L_ERROR, ("Explanation: %s\n", errstr));
}
	

/*
 * this function just look for a NetNumber in the routing table,
 * no check is done for the validity of the entry
 */

RT_entry *rt_blookup (NetNumber)
at_net_al NetNumber;
{

	RT_entry *ptree = &RT_table_start;
	at_net_al LowEnd;
/*
	dPrintf(D_M_RTMP_LOW, D_L_ROUTING, ("%s : Lookup for Net=%d\n",
		 "rt_blookup", NetNumber));
*/	
	while (ptree) {

		if (NetNumber > ptree->NetStop) {
/*
			dPrintf(D_M_RTMP_LOW, D_L_ROUTING, ("%s : Go Right from  #%d\n",
				 "rt_blookup", ptree->NextIRNet));
*/
			ptree = ptree->right;
			continue;
		}
		else {
		   if (ptree->NetStart) 
			LowEnd = ptree->NetStart;
		   else
			LowEnd = ptree->NetStop;

		   if (NetNumber < LowEnd ) {
/*
			dPrintf(D_M_RTMP_LOW, D_L_ROUTING, ("%s : Go Left from  #%d\n",
				 "rt_blookup", ptree->NextIRNet));
*/
			ptree = ptree->left;
			continue;
		   }
		   
		   /* we're in the range (either extended or not)
		    * return the entry found.
		    */

/*			dPrintf(D_M_RTMP_LOW, D_L_ROUTING, ("%s : found %04d-%04d Port=%d State=0x%x\n",
				"rt_blookup", ptree->NetStart, ptree->NetStop, ptree->NetPort,
				ptree->EntryState));
*/

		   return (ptree);
		}	
	}

	dPrintf(D_M_RTMP_LOW, D_L_ROUTING, ("%s : %04d : NOT FOUND\n",
		 "rt_blookup", NetNumber));
	return ((RT_entry *)NULL);
}


/* Routing table btree insert routine
 *  Uses a RT_entry parameter as the input, the insert is sorted in
 *  the tree on the NetStop field. Provision is made for non extented
 *  net (ie NetStart = 0).   
 *  The function returns the element where the new entry was inserted, or
 *  NULL if the insert didn't work. (In this cas there is a problem with
 *  the tree coherency...
 *  
 */


RT_entry *rt_binsert (NewEntry)
RT_entry *NewEntry;
{
	RT_entry *ptree = &RT_table_start;

	register at_net_al NetStart = NewEntry->NetStart;
	register at_net_al NetStop  = NewEntry->NetStop;

	dPrintf(D_M_RTMP_LOW, D_L_ROUTING, ("rt_binsert: for Net %d-%d state=x%x NextIR %d:%d\n",
		 NetStart, NetStop, NewEntry->EntryState,NewEntry->NextIRNet, NewEntry->NextIRNode));

	if (ptree == (RT_entry *)NULL) {
		*ptree = *NewEntry;
		at_state.flags |= AT_ST_RT_CHANGED;
		return (NewEntry);
	}
	

	while (ptree) {

		if (NetStop > ptree->NetStop) { /* walk the right sub-tree */
			if (ptree->right)
				ptree = ptree->right;
			else {
				ptree->right = NewEntry;
				at_state.flags |= AT_ST_RT_CHANGED;
				return (ptree);
			}
		}
		else { /* walk the left sub-tree */
			if (ptree->left) 
				ptree = ptree->left;
			else {
			    	ptree->left = NewEntry;
				at_state.flags |= AT_ST_RT_CHANGED;
				return (ptree);
			}
		}

	}	

	dPrintf(D_M_RTMP, D_L_WARNING, ("%s : ERROR NOT INSERTED Net %d-%d\n",
		 "rt_binsert", NetStart, NetStop));
	return ((RT_entry *)NULL);
}

RT_entry *rt_insert(NStop, NStart, NxNet, NxNode, NtDist, NtPort, EntS) 
     at_net_al NStop, NStart, NxNet;
     at_node NxNode;
     u_char NtDist, NtPort, EntS;
{
    RT_entry *New; 
    if ((New = RT_table_freelist)) {
	RT_table_freelist = RT_table_freelist->right; 
    } else 
	return ((RT_entry *)NULL);
    New->right = NULL; 
    New->NetStop = NStop; 
    New->NetStart = NStart; 
    New->NextIRNet = NxNet; 
    New->NextIRNode = NxNode; 
    New->NetDist = NtDist; 
    New->NetPort = NtPort; 
    New->EntryState = EntS; 
    bzero(New->ZoneBitMap, sizeof(New->ZoneBitMap)); 
	at_state.flags |= AT_ST_RT_CHANGED; 
	return(rt_binsert(New)); 
}

/*
	dPrintf(D_M_RTMP_LOW, D_L_ROUTING, ("%s : %04d : NOT FOUND\n",
		 "rt_blookup", NetNumber));
 * Routing table btree deletion routine
 *
 */

RT_entry *rt_bdelete (NetStop, NetStart)
     at_net_al NetStop, NetStart;
{

	RT_entry *rt_found, *pprevious, *pnext, *pnextl, *psub;
	at_net_al LowEnd;

	rt_found = &RT_table_start;

	dPrintf(D_M_RTMP_LOW, D_L_ROUTING, ("%s : Delete %d-%d\n",
		 "rt_bdelete", NetStart, NetStop));

	while (rt_found) {

		if (NetStop > rt_found->NetStop) {
			pprevious = rt_found;
			rt_found = rt_found->right;
			continue;
		}
		else {
		
		   /* non extended nets cases */

		   if (rt_found->NetStart) 
			LowEnd = rt_found->NetStart;
		   else
			LowEnd = rt_found->NetStop;

		  if (NetStop < LowEnd) {
			pprevious = rt_found;
			rt_found = rt_found->left;
			continue;
		   }
		   
		   /* we're in the range (either extended or not)
		    * return the entry found.
		    */

		   break;
		}	
	}

	dPrintf(D_M_RTMP, D_L_ROUTING, ("%s : Delete %d-%d found to delete %d-%d\n",
		 "rt_bdelete", NetStart, NetStop, rt_found->NetStart,rt_found->NetStop));

	if (rt_found) {



		   /* we found the entry, now reorg the sub-trees
		    * spanning from our node.
		    */

		    if ((pnext = rt_found->right)) {

				/* Tree pruning: take the left branch of the current
				 * node and place it at the lowest left branch
				 * of the current right branch 
				 */

				psub = pnext;

				/* walk the Right/Left sub tree from current node */

				while ((pnextl = psub->left))
					psub = pnextl;	
				
				/* plug the old left tree to the new ->Right leftmost node */	
				
				psub->left = rt_found->left;
						

		    } else {	 /* only left sub-tree, simple case */

				pnext = rt_found->left;
		    }
			
			/* Now, plug the current node sub tree to the good pointer of 
             * our parent node.
             */


			if (pprevious->left == rt_found)
				pprevious->left = pnext;
			else
				pprevious->right = pnext;	

			/* clean-up entry and add to the free-list */

			at_state.flags |= AT_ST_RT_CHANGED;
			return(rt_found);
	}

	else { /* Trying to delete something that doesn't exist? */

		dPrintf(D_M_RTMP, D_L_WARNING, ("%s : %d NOT Removed\n",
			"rt_bdelete", NetStop));

		return ((RT_entry *)NULL);
	}

				
}
					

RT_entry *rt_sortedshow(parent)
RT_entry *parent;
{
	RT_entry *me;
	
	me = parent;

	if (parent == NULL) {
		me = &RT_table_start;
		while (me) 
			if (me->left) {
				parent = me;
				me = me->left;
			}
/*		parent = parent->parent; */
	}
	return (parent);
}

/*
 * debug only: display the contents of the routing table
 */

void rt_show ()
{
	RT_entry *ptree;
	int i=0;

	ptree = &RT_table[0];

	while (ptree && i < 600 ) {
		if (ptree->NetStop) { 
			dPrintf(D_M_RTMP_LOW, D_L_VERBOSE,
				("%4d-%4d IR=%d:%d Dist=%d\n",
		 		ptree->NetStop, ptree->NetStart, ptree->NextIRNet,
		  		ptree->NextIRNode, (short)ptree->NetDist));
		} else {
			dPrintf(D_M_RTMP_LOW, D_L_VERBOSE,
				("%04d : * FREE ENTRY\n", i));
		}
		ptree++;
	i++;
	}
}

/*
 * prepare the indexing of the free entries in the RTMP table
 */

rt_table_init()
{
	short i;

	if ((RT_table = (RT_entry *)_MALLOC(sizeof(RT_entry)*RT_maxentry,
					    M_RTABLE, M_WAITOK)) == NULL) {
		dPrintf(D_M_RTMP, D_L_WARNING, 
			("rtmptable: Can't allocate RT_table\n"));
		return (ENOMEM);
	}
	if ((ZT_table = (ZT_entry *)_MALLOC(sizeof(ZT_entry)*ZT_maxentry,
					    M_RTABLE, M_WAITOK)) == NULL) {
		dPrintf(D_M_RTMP, D_L_WARNING, 
			("rtmptable: Can't allocate ZT_table\n"));
		return (ENOMEM);
	}
	dPrintf(D_M_RTMP, D_L_STARTUP, ("rt_table_init called\n"));
	bzero(&RT_table[0], sizeof(RT_entry)* RT_maxentry);
	for (i= 1 ; i < RT_maxentry ; i++) {
        	(&RT_table[i-1])->right = &RT_table[i];
	}
	RT_table_freelist = &RT_table[0];

	at_state.flags |= AT_ST_RT_CHANGED;
	at_state.flags |= AT_ST_ZT_CHANGED;
	bzero(&RT_table_start, sizeof(RT_entry));

	/* also clean up the ZIP table */

	bzero(&ZT_table[0], sizeof(ZT_entry)* ZT_maxentry);
	ErrorRTMPoverflow = 0;
	ErrorZIPoverflow = 0;
	return(0);
}

/* 
 * zt_add_zone: add a zone name in the zone table.
 */

zt_add_zone(name, length)
char *name;
short length;
{
	at_nvestr_t zname;
	bcopy(name, &zname.str, length);
	zname.len = length;
	return (zt_add_zonename(&zname));
}

/* 
 * zt_add_zonename: add a zone name in the zone table.
 */

int zt_add_zonename(zname)
at_nvestr_t *zname;
{
	register short res,i;

	if (res = zt_find_zname(zname))
		return(res);

	for (i = 0; i < ZT_maxentry ; i++) {
		if (ZT_table[i].ZoneCount == 0 && ZT_table[i].Zone.len == 0) {/* free entry */
			ZT_table[i].Zone = *zname;
			dPrintf(D_M_RTMP, D_L_VERBOSE, ("zt_add_zonename: zone #%d %s len=%d\n",
				i, ZT_table[i].Zone.str, ZT_table[i].Zone.len));
			at_state.flags |= AT_ST_ZT_CHANGED;
			return(i+1);
		}
	}
	/* table full... */
	return (ZT_MAXEDOUT);
}

/* Adjust zone counts for a removed network entry.
 * If the ZoneCount of a zone reaches zero, delete the zone from the zone table
 */
void zt_remove_zones(zmap)
u_char *zmap;
{

	register	u_short i,j, Index;

	for (i=0; i< ZT_BYTES ; i++) {

		if (zmap[i]) {
			for (j=0; j < 8 ; j++)
				if ((zmap[i] << j) & 0x80) {
					Index = i*8 + j;	/* get the index in ZT */
						/* 1-23-97 this routine caused a crash once, presumably
					       zmap bits beyond ZT_table size got set somehow.
                           prevent that here
						 */
					if (Index >= ZT_maxentry) {
						dPrintf(D_M_RTMP, D_L_ERROR,
							("zt_remove_zones: index (%d) GT ZT_maxentry (%d) (zmap:%d)\n",
							Index,ZT_maxentry,i));
						return;
					}
					dPrintf(D_M_RTMP, D_L_VERBOSE,
						("zt_remove_zones: zone #%d %s was=%d\n", Index,
						ZT_table[Index].Zone.str, ZT_table[Index].ZoneCount));
					if (ZT_table[Index].ZoneCount > 0) 
						ZT_table[Index].ZoneCount--;
					if (ZT_table[Index].ZoneCount == 0)
							ZT_table[Index].Zone.len = 0;
					at_state.flags |= AT_ST_ZT_CHANGED;
				}
		}
	}
}



/*
 * zt_compute_hash: compute hash index from the zone name string
 */

short zt_compute_hash(zname)
at_nvestr_t *zname;
{
	register u_short checksum=0, i;
	register char c1;

	/* apply the upper name + DDP checksum algorithm */

	for (i= 0 ; i < zname->len; i++) {

			/* upperize the character */

			c1 = zname->str[i];
            if (c1 >= 'a' && c1 <= 'z')
                   c1 += 'A' - 'a';
            if (c1 & 0x80)
                c1 = upshift8(c1);

			/* DDP Checksum */

			checksum += c1;
			checksum = ((checksum & 0x8000) ?
				(checksum << 1 | 1) : (checksum << 1));
	}

	dPrintf(D_M_RTMP_LOW, D_L_ROUTING, ("zt_comphash: value computed for zone=%s h=%d\n",
		zname->str, checksum));

	if (checksum)
		return (checksum);
	else
		return (0xffff);

}

/* 
 * zt_upper_zname: translate the name string into uppercase
 */

void zt_upper_zname(zname)
at_nvestr_t *zname;
{
	register short i;
	register char c1;

	for (i= 0 ; i < zname->len; i++) {

			c1 = zname->str[i];
            if (c1 >= 'a' && c1 <= 'z')
                   c1 += 'A' - 'a';
            if (c1 & 0x80)
                c1 = upshift8(c1);

			zname->str[i] = c1;
	}
}

/*
 * zt_get_zmcast: calcularte the zone multicast address for a
 *                    given zone name. 
 *                    Returns the result in "buffer"
 */

zt_get_zmcast(ifID, zname, buffer)
     at_ifaddr_t *ifID;		/* we want to know the media type */
     at_nvestr_t *zname;	/* source name for multicast address */
     char *buffer;		/* resulting Zone Multicast address */
{
	u_short h;

	h = zt_compute_hash(zname);

/*
 * Find a nice way to decide if it is TokenRing or Ethernet for
 * the Multicast address computation....
 */

	if (ifID->aa_ifp->if_type != IFT_ISO88025) { /* token ring */

		/* Ethernet case */

		buffer[0] = 0x09;
		buffer[1] = 0x00;
		buffer[2] = 0x07;
				/* no router, use cable multicast */
		if (MULTIHOME_MODE && ifID->ifRouterState == NO_ROUTER ) {
			buffer[3] = buffer[4] = buffer[5] =  0xff;
		}
		else {
			buffer[3] = 0x00;
			buffer[4] = 0x00;
			buffer[5] = h % 0xFD;
		}
		dPrintf(D_M_RTMP_LOW, D_L_ROUTING, ("zt_get_multi: computed for h=%d %x %x\n",
				h, *(u_int *)&buffer[0], *(u_short *)&buffer[4]));
 
		return(6); /* returns Multicast address length */

	}
	else {
		 /* assume it is token ring: note for the magic number computation,
		  * first see Inside Mac Page 3-10, there is 20 multicast addresses
		  * for TLAP, and they are from 0xC000 0000 0008 00 to 0xC000 0200 0000 00
		  */
		buffer[0] = 0xC0;
		buffer[1] = 0x00;
		*(u_int *)&buffer[2] = 1 << ((h % 19) + 11);
		dPrintf(D_M_RTMP, D_L_WARNING,("zt_get_multi: BROAD not found forr h=%d \n",
			 h));
		return(6);
	}



}

/*
 * zt_ent_zindex: return the first zone index found in the zone map
 * return the entry number+1 in the Zone Table, or zero if not found
 */

int zt_ent_zindex(zmap)
u_char *zmap;
{
	u_short i,j;


	for (i = 0 ; i < ZT_BYTES ; i++)

		if (zmap[i]) 
			for (j = 0 ; j < 8 ; j++)
				if ((zmap[i] << j) & 0x80)
					return (8*i + j +1);

	return (0);
}
/*
 * zt_ent_zcount: count the number of actives zone for a routing entry
 */

zt_ent_zcount(ent)
RT_entry *ent;
{
	register u_char *zmap;
	register u_short i,j;
	register int	   zone_count = 0 ;


	if (!RT_ALL_ZONES_KNOWN(ent))
			return (0);
	zmap = ent->ZoneBitMap;

	for (i = 0 ; i < ZT_BYTES ; i++) {

		if (*zmap) 

			for (j = 0 ; j < 8 ; j++)
				if ((*zmap << j) & 0x80)
					zone_count++;
		zmap++;
	}

	return (zone_count);
}

/*
 * zt_find_zname: match a zone name in the zone table and return the entry if found
 */
zt_find_zname(zname)
at_nvestr_t *zname;
{
	register short i, j, found;
	register char c1, c2;


	if (!zname->len)
		return(0);

	for (i = 0 ; i < ZT_maxentry ; i++) {
			if (!ZT_table[i].ZoneCount || zname->len != ZT_table[i].Zone.len)
					continue;

			found = 1; /* did we get the right one? */

			for (j = 0 ; j < zname->len ; j++) {
	            c1 = zname->str[j];
                c2 = ZT_table[i].Zone.str[j];
                if (c1 >= 'a' && c1 <= 'z')
                        c1 += 'A' - 'a';
                if (c2 >= 'a' && c2 <= 'z')
                        c2 += 'A' - 'a';
                if (c1 & 0x80)
                        c1 = upshift8(c1);
                if (c2 & 0x80)
                        c2 = upshift8(c2);
                if (c1 != c2) {
                        found = 0;
						break;
				}
			}

			if (found)
				return (i+1);
	}

	return(0);
}

	
/*
 * zt_set_zmap: set a bit for the corresponding zone map in an entry bitmap
 */
void zt_set_zmap(znum, zmap)
     u_short znum;
     char *zmap;
{
	register u_short num = znum -1;

	if (!(zmap[num >> 3] & 0x80 >> (num % 8))) {
		zmap[num >> 3] |= 0x80 >> (num % 8);
		ZT_table[num].ZoneCount++;
	}
}


/*
 * zt_clr_zmap: clear a bit for the corresponding zone map in an entry bitmap
 */
void zt_clr_zmap(znum, zmap)
     u_short znum;
     char *zmap;
{
	register u_short num = znum -1;

	if (zmap[num >> 3] & 0x80 >> (num % 8)) {
		zmap[num >> 3] ^= 0x80 >> (num % 8);
		ZT_table[num].ZoneCount--;
	}
}


/*
 * routing_needed : 
 * This function performs the actual lookup and forward of packets
 * send to the box for routing.
 *
 * The destination network is looked up in our tables, and if we
 * know the next IR to send the packet to, we forward the packet
 * on the right port.
 *
 * If the destination is unknown, we simply dump the packet.
 */

void routing_needed(mp, ifID, bypass)
     gbuf_t   *mp;
     at_ifaddr_t *ifID;
     char bypass;	/* set by special socket handlers */
{

	register at_ddp_t *ddp;
	register int       msgsize;
	register RT_entry *Entry;
	register gbuf_t *tmp_m;

	/* first check the interface is up and forwarding */

	if (!ifID) {
		dPrintf(D_M_RTMP, D_L_WARNING, 
			("routing_needed: non valid IFID!\n"));
		gbuf_freel(mp);		
		return;
	}
	if ((ifID->ifRoutingState < PORT_ONLINE)) {
		dPrintf(D_M_RTMP, D_L_WARNING, 
			("routing_needed: port %d not online yet\n",
			 ifID->ifPort));
		gbuf_freel(mp);		
		return;
	}

	ddp = (at_ddp_t *)gbuf_rptr(mp);
	msgsize = DDPLEN_VALUE(ddp);
	for (tmp_m = gbuf_next(mp); tmp_m; tmp_m = gbuf_next(tmp_m))
		msgsize += DDPLEN_VALUE(((at_ddp_t *)gbuf_rptr(tmp_m)));
	
	if (ddp->hopcount++ > 15) {
		dPrintf(D_M_RTMP, D_L_WARNING,
			("routing_needed: drop packet for %d:%d, hopcount too high\n",
			NET_VALUE(ddp->dst_net), ddp->dst_node));
		gbuf_freel(mp);
		snmpStats.dd_hopCount++;
		return; /* was return(1); */
	}

	if ((Entry = rt_blookup(NET_VALUE(ddp->dst_net)))) {
	
		dPrintf(D_M_RTMP_LOW, D_L_ROUTING,
			("routing_needed: FOUND for %d.%d p=%d to %d.%d \n",
			NET_VALUE(ddp->dst_net), ddp->dst_node, ifID->ifPort,
			Entry->NextIRNet, Entry->NextIRNode));

		/* somehow, come to that point... */

		/* if multihomed - need to set source address to the interface
		 * the packet is being sent from.
		 */
		if (MULTIHOME_MODE) {
			NET_ASSIGN(ddp->src_net, ifID_table[Entry->NetPort]->ifThisNode.s_net);
			ddp->src_node = ifID_table[Entry->NetPort]->ifThisNode.s_node;
		}

		ifID->ifStatistics.fwdPkts++;
		ifID->ifStatistics.fwdBytes += msgsize;

		if (Entry->NetDist)  /* net not directly connected */
			ddp_router_output(mp, ifID_table[Entry->NetPort], AT_ADDR,
				 Entry->NextIRNet, Entry->NextIRNode, 0);
		else {/* we are directly on this net */

			/* we want to avoid duplicating broadcast packet on the same net,
			 * but special sockets handlers are ok to do that (mainly for
			 * for loopback purpose). So, if the "bypass" flag is set, we don't
			 * check for that test... [Problem was "movietalk"].
			 */

			if (bypass || ifID_table[Entry->NetPort] != ifID) 
				ddp_router_output(mp, ifID_table[Entry->NetPort], AT_ADDR,
				 NET_VALUE(ddp->dst_net), ddp->dst_node, 0);
			else {
				dPrintf(D_M_RTMP, D_L_ROUTING,
					("routing_needed: bad loopback for add %d.%d from port %d (%d.%d)\n",
					 NET_VALUE(ddp->dst_net), ddp->dst_node, ifID->ifPort,
					 NET_VALUE(ddp->src_net), ddp->src_node));
				ifID->ifStatistics.droppedPkts++;
				ifID->ifStatistics.droppedBytes += msgsize;

				gbuf_freel(mp);
				return; /* was return (2); */
			}
 

		}
	}
	else {
		dPrintf(D_M_RTMP, D_L_ROUTING,
			("routing_needed: NOT FOUND for add %d.%d from port %d our %d.%d\n",
			 NET_VALUE(ddp->dst_net), ddp->dst_node, ifID->ifPort,
			 ifID_home->ifThisNode.s_net,
			 ifID_home->ifThisNode.s_node));

		ifID->ifStatistics.droppedPkts++;
		ifID->ifStatistics.droppedBytes += msgsize;
		snmpStats.dd_noRoutes++;

		gbuf_freel(mp);
		return; /* was return (2); */

	}
	/*	return(0); */
} /* routing_needed */

ZT_entryno *zt_getNextZone(first)
	int	first;	
	/* a call made with first = TRUE returns the first valid entry in
	   the ZT_table, if first != TRUE, then then each call returns the
	   next valid entry in the table. The next call after the last
	   valid entry was read returns NULL
	*/
{
	int 		i;
	static int 	idx=0;
	static ZT_entryno	zte;
	
	if (!ZT_table)
		return NULL;

	if (first)
		idx=0;

	for (i=idx; i<ZT_maxentry; i++) {
		if (ZT_table[i].ZoneCount)
			break;
	}
	if (i<ZT_maxentry) {
		idx = i+1;
		zte.zt = ZT_table[i];
		zte.entryno = i;
		return(&zte);
	}
	else
		return(NULL);
}

RT_entry *rt_getNextRoute(first)
	int	first;	

/* a call made with first = TRUE returns the first valid entry in
   the RT_table, if first != TRUE, then then each call returns the
   next valid entry in the table. The next call after the last
   valid entry was read returns NULL
*/

{
	int 		i;
	static int 	idx=0;
	
	if (!RT_table)
		return(NULL);

	if (first)
		idx=0;

	for (i=idx; i<RT_maxentry; i++) {
		if (RT_table[i].EntryState != RTE_STATE_UNUSED)
			break;
	}
	if (i<RT_maxentry) {
		idx = i+1;
		return(&RT_table[i]);
	}
	else
		return(NULL);
}


getRtmpTableSize()
{
	register int i;
	register RT_entry *rt;
	static 	int size=0;

	if(!(at_state.flags &AT_ST_RT_CHANGED))		
		return(size);

	for (i=RT_maxentry,rt = &RT_table[RT_maxentry-1]; i; i--,rt--)
		if (rt->EntryState != RTE_STATE_UNUSED) {
			size = i;
			return(i);
		}
	return(0);
}

getZipTableSize()
{
	register int i;
	register ZT_entry *zt;
	static	int size=0;

	if (!(at_state.flags & AT_ST_ZT_CHANGED))
		return(size);

	for (i=ZT_maxentry,zt = &ZT_table[ZT_maxentry-1]; i; i--,zt--)
		if (zt->ZoneCount) {
			size = i;
			return(i);
		}
	return(0);
}

getRtmpTable(d,s,c)
     RT_entry	*d;		/* destination */
     int 	s;		/* starting entry */
     int	c;		/* # entries to copy */
{
	register int i,n=0;
	register RT_entry	*rt;

	for(i=s,rt=&RT_table[s]; i<RT_maxentry && n<c; rt++,i++)
		if (rt->EntryState != RTE_STATE_UNUSED) {
			*d++ = *rt;
			n++;
		}
}

getZipTable(d,s,c)
     ZT_entry	*d;		/* destination */
     int 	s;		/* starting entry */
     int	c;		/* # entries to copy */
{

	bcopy(&ZT_table[s], d, c*sizeof(ZT_entry));
}

at_nvestr_t *getRTRLocalZone(ifz)
     zone_usage_t *ifz;
{
	char *zmap;
	RT_entry	*route;
	int i, j, index;
	int  zcnt=0;		/* zone we're pointing to in the list */
	char zonesChecked[ZT_BYTES];
	at_ifaddr_t *ifID;

	if (ifz->zone_index < 0) {
		return((at_nvestr_t*)NULL);
	}
	bzero(zonesChecked,sizeof(zonesChecked));
	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
		if (!(route = rt_blookup(ifID->ifThisNode.s_net))) {
			return((at_nvestr_t*)NULL);
		}	
		zmap=route->ZoneBitMap;
		dPrintf(D_M_RTMP_LOW, D_L_USR1,
			("getRTRLocal: i/f %s, net:%d\n",ifID->ifName, 
			 ifID->ifThisNode.s_net));
		for (i = 0 ; i < ZT_BYTES; i++) {
		  if (zmap[i]) {
		    for (j = 0; j < 8 ; j++)
		      if (  (zmap[i]  & (0x80 >> j)) &&
			    !(zonesChecked[i] & (0x80 >> j)) 
			    ) {
			zonesChecked[i] |=  (0x80 >> j);
			if (ifz->zone_index == zcnt) {
			  index = i * 8 + j;
			  getIfUsage(index, &ifz->zone_iflist);
			  ifz->zone_name = ZT_table[index].Zone;
			  dPrintf(D_M_RTMP_LOW, D_L_USR1,
				  ("getRTRLocal:zmap:%8x zcnt:%d\n",
				   *(int*)zmap, zcnt));
			  ifz->zone_index = index+1;
			  return(&ZT_table[index].Zone);
			}
			zcnt++;
		      }
		  }
		}
	}
	dPrintf(D_M_RTMP_LOW, D_L_USR1,
		("getRTRLocal: returning NULL last ent:%d net:%d zmap:%08x\n",
		 (ifID ? ifID->ifPort : 0),
		 (ifID ? ifID->ifThisNode.s_net : 0),*(int*)zmap));
	ifz->zone_name.len = 0;
	return((at_nvestr_t*)NULL);
} /* getRTRLocalZone */

void getIfUsage(zone, ifs_in_zone)
     int zone;
     at_ifnames_t *ifs_in_zone;

/* sets the interface name in each element of the array for each I/F in the
   requested zone. The array has a 1:1 correspondence with the
   ifID_table. Zone is assumed to be valid and local, so if we're in
   single port mode, we'll set the home port and thats it.
*/
{
	u_int	zmi;    /* zone map index for zone */
	u_char	zmb;	/* zone map bit mask for zone */
	RT_entry	*route;
	int cnt=0;
	at_ifaddr_t 	*ifID;

	if (!MULTIPORT_MODE) {
		strncpy(ifs_in_zone->at_if[cnt], ifID_home->ifName, 
			IFNAMESIZ);
		return;
	}
	bzero(ifs_in_zone, sizeof(at_ifnames_t));
	zmi = zone>>3;
	zmb = 0x80>>(zone % 8);
	dPrintf(D_M_NBP_LOW, D_L_USR3, ("get_ifs znum:%d zmi%d zmb:%x\n",
		zone, zmi, zmb));
	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
		if (!(route = rt_blookup(ifID->ifThisNode.s_net)))
			return;
		if (route->ZoneBitMap[zmi] & zmb) {
			dPrintf(D_M_NBP_LOW, D_L_USR3, ("zone in port %d \n",
				route->NetPort));
			strncpy(ifs_in_zone->at_if[cnt], 
				ifID_table[route->NetPort]->ifName, IFNAMESIZ);
			cnt++;
		}
	}
	return;
} /* getIfUsage */
