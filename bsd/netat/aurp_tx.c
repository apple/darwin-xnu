/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
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
/*
 *	Copyright (c) 1996 Apple Computer, Inc. 
 *
 *		Created April 8, 1996 by Tuyen Nguyen
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 *
 *	File: tx.c
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
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/routing_tables.h>
#include <netat/at_pcb.h>
#include <netat/aurp.h>
#include <netat/debug.h>

/*
 * Any AURP protocol or appletalk data (ddp) packets flowing through
 *  are inserted into the kernel aurpd process's (atalk) input queue.
 * Assume here that we deal with single packets, i.e., someone earlier
 *  in the food chain has broken up packet chains.
 */
void AURPsend(mdata, type, node)
	gbuf_t *mdata;
	int type, node;
{
	struct aurp_domain *domain;
	gbuf_t *m;
	int msize = AT_WR_OFFSET+32+IP_DOMAINSIZE;

	/* Add the domain header */
	if ((m = gbuf_alloc(msize, PRI_MED)) == 0) {
		gbuf_freem(mdata);
		dPrintf(D_M_AURP, D_L_WARNING, ("AURPsend: gbuf_alloc failed\n"));
		return;
	}
	gbuf_wset(m,msize);
	gbuf_rinc(m,AT_WR_OFFSET+32);
	gbuf_cont(m) = mdata;
	domain = (struct aurp_domain *)gbuf_rptr(m);
	domain->dst_length = IP_LENGTH;
	domain->dst_authority = IP_AUTHORITY;
	domain->dst_distinguisher = IP_DISTINGUISHER;
	domain->src_length = IP_LENGTH;
	domain->src_authority = IP_AUTHORITY;
	domain->src_distinguisher = IP_DISTINGUISHER;
	domain->src_address = aurp_global.src_addr;
	domain->version = AUD_Version;
	domain->reserved = 0;
	domain->type = type;
	domain->dst_address = aurp_global.dst_addr[node];
	atalk_to_ip(m);
}

/*
 * Called from within ddp (via ddp_AURPsendx) to handle data (DDP) packets
 *  sent from the AppleTalk stack, routing updates, and routing info
 *  initialization.
 */
void AURPcmdx(code, mdata, param)
	int code;
	gbuf_t *mdata;
	int param;
{
	unsigned char node;
	gbuf_t *mdata_next;

	if (mdata == 0)
		return;
	if (aurp_gref == 0) {
		if (code != AURPCODE_DEBUGINFO)
			AURPfreemsg(mdata);
		return;
	}

	switch (code) {
	case AURPCODE_DATAPKT: /* data packet */
		node = (unsigned char)param;
		if (gbuf_next(mdata)) {
			mdata_next = gbuf_next(mdata);
			gbuf_next(mdata) = 0;
			AURPsend(mdata, AUD_Atalk, node);
			do {
				mdata = mdata_next;
				mdata_next = gbuf_next(mdata);
				gbuf_next(mdata) = 0;
				/* Indicate non-AURP packet, node id of peer */
				AURPsend(mdata, AUD_Atalk, node);
			} while (mdata_next);
		} else
			AURPsend(mdata, AUD_Atalk, node);
		break;

	case AURPCODE_RTUPDATE:
		AURPrtupdate((RT_entry *)mdata, param);
		break;

	case AURPCODE_DEBUGINFO: /* debug info */
		dbgBits = *(dbgBits_t *)mdata;
		net_port = param;
		break;

	default:
		dPrintf(D_M_AURP, D_L_ERROR, ("AURPcmdx: bad code, %d\n", code));
	}
}
