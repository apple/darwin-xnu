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
 *	Copyright (c) 1996 Apple Computer, Inc. 
 *
 *		Created April 8, 1996 by Tuyen Nguyen
 *		Modified for Kernel execution, May, 1996, Justin C. Walker
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 *
 *	File: rx.c
 */
#ifdef AURP_SUPPORT

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
 * Not using the stream queue for data; keep this around to handle
 *  requests from the user proc (mostly setup).
 */
int
aurp_wput(gref, m)
	gref_t *gref;
	gbuf_t *m;
{
	register ioc_t *iocbp;
	register gbuf_t *mdata;
	register int temp, error;

	switch (gbuf_type(m)) {

	case MSG_IOCTL:
		iocbp = (ioc_t *)gbuf_rptr(m);
		switch (iocbp->ioc_cmd) {
		case AUC_CFGTNL: /* set up a tunnel, init the AURP daemon */
			mdata = gbuf_cont(m);
			temp = (int)(*gbuf_rptr(mdata));
			if (temp != dst_addr_cnt) {
				AURPiocnak(gref, m, ENOSPC);
				return 0;
			}
			if ((error = aurpd_start()) != 0) {
				AURPiocnak(gref, m, error);
				return 0;
			}
			if (AURPinit()) {
				AURPiocnak(gref, m, ENOMEM);
				return 0;
			}
			ddp_AURPfuncx(AURPCODE_AURPPROTO, 0, 0);
			AURPaccess();
			break;

		case AUC_SHTDOWN: /* shutdown AURP operation */
			AURPshutdown();
			break;

		case AUC_EXPNET: /* configure networks to be exported */
		case AUC_HIDENET: /* configure networks to be hiden */
			mdata = gbuf_cont(m);
			net_access_cnt = (gbuf_len(mdata))/sizeof(short);
			if ((net_access_cnt==0) || (net_access_cnt>AURP_MaxNetAccess)) {
				AURPiocnak(gref, m, EINVAL);
				return 0;
			}
			bcopy(gbuf_rptr(mdata), net_access,
			      gbuf_len(mdata));
			if (iocbp->ioc_cmd == AUC_EXPNET)
				net_export = 1;
			break;

		case AUC_UDPPORT:
			mdata = gbuf_cont(m);
			aurp_global.udp_port = *(char *)gbuf_rptr(mdata);
			break;

		case AUC_NETLIST:
			mdata = gbuf_cont(m);
			/*
			 * Compute # addrs, Save for later check
			 * We cheat with a shift.
			 */
			dst_addr_cnt = ((gbuf_len(mdata)) >> 2)-1;
			bcopy(gbuf_rptr(mdata), &aurp_global.dst_addr,
			      gbuf_len(mdata));
			aurp_global.src_addr = aurp_global.dst_addr[0];
			aurp_global.dst_addr[0] = 0;
			break;

		default:
			AURPiocnak(gref, m, EINVAL);
			return 0;
		}
		AURPiocack(gref, m);
		break;

	default:
		dPrintf(D_M_AURP, D_L_WARNING,
			("aurp_wput: bad msg type=%d\n", gbuf_type(m)));
		gbuf_freem(m);
		break;
	}

	return 0;
}

/*
 * Insert an appletalk packet into the appletalk stack.
 * If it's an AURP data packet, just send it up; if it's AURP protocol,
 *  switch out here.
 */

int
at_insert(m, type, node)
	register gbuf_t *m;
	register unsigned int type, node;
{
	register aurp_hdr_t *hdrp;
	register aurp_state_t *state;

	if (type == AUD_Atalk)
		/* non-AURP proto packet */
		ddp_AURPfuncx(AURPCODE_DATAPKT, m, node);
	else
	{	/* AURP proto packet */
		state = (aurp_state_t *)&aurp_state[node];
		state->tickle_retry = 0;
		hdrp = (aurp_hdr_t *)gbuf_rptr(m);

		switch (hdrp->command_code) {
		case AURPCMD_RIUpd:
			AURPrcvRIUpd(state, m); break;

		case AURPCMD_RIReq:
			AURPrcvRIReq(state, m); break;

		case AURPCMD_RIRsp:
			AURPrcvRIRsp(state, m); break;

		case AURPCMD_RIAck:
			AURPrcvRIAck(state, m); break;

		case AURPCMD_ZReq:
			AURPrcvZReq(state, m); break;

		case AURPCMD_ZRsp:
			AURPrcvZRsp(state, m); break;

		case AURPCMD_OpenReq:
			AURPrcvOpenReq(state, m); break;

		case AURPCMD_OpenRsp:
			AURPrcvOpenRsp(state, m); break;

		case AURPCMD_Tickle:
			AURPrcvTickle(state, m); break;

		case AURPCMD_TickleAck:
			AURPrcvTickleAck(state, m); break;

		case AURPCMD_RDReq:
			AURPrcvRDReq(state, m); break;

		default:
			dPrintf(D_M_AURP, D_L_WARNING,
				("at_insert: bad proto cmd=%d\n",
				hdrp->command_code));
			gbuf_freem(m);
		}
	}

	return 0;
}

