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
 *	Copyright (c) 1997-1999 Apple Computer, Inc.
 *	All Rights Reserved.
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)at_pcb.c	8.2 (Berkeley) 1/4/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <kern/kern_types.h>
#include <kern/zalloc.h>
#include <kern/queue.h>

#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/ddp.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/at_var.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

extern struct atpcb ddp_head;
extern struct atpcb *atp_inputQ[];
extern CCB *adsp_inputQ[];
extern at_ifaddr_t *ifID_home;
extern struct {
  void (*func)();
  } ddp_handler[];

int DDP_chksum_on = FALSE;
int DDP_slfsnd_on = FALSE;

zone_t atpcb_zone;

void at_memzone_init()
{
	vm_size_t str_size;

	str_size = (vm_size_t)sizeof(struct atpcb);
	atpcb_zone = (zone_t)zinit(str_size, 1000*str_size, 8192, "atpcb zone");
}

int at_pcballoc(so, head)
	struct socket *so;
	struct atpcb *head;
{
	register struct atpcb *pcb;

	pcb = (struct atpcb *)zalloc(atpcb_zone);
	if (pcb == NULL)
		return (ENOBUFS);
	bzero((caddr_t)pcb, sizeof(*pcb));

	/* set the flags to the system defaults */
	if (DDP_chksum_on)
		pcb->ddp_flags |= DDPFLG_CHKSUM;
	else
		pcb->ddp_flags &= ~DDPFLG_CHKSUM;
	if (DDP_slfsnd_on)
		pcb->ddp_flags |= DDPFLG_SLFSND;
	else
		pcb->ddp_flags &= ~DDPFLG_SLFSND;

	pcb->atpcb_head = head;
	pcb->atpcb_socket = so;
	atalk_lock();	/* makes sure the list is locked while inserting atpcb */
	if (head)
	    insque((queue_t)pcb, (queue_t)head);
	so->so_pcb = (caddr_t)pcb;
	atalk_unlock();

	return (0);
}

int at_pcbdetach(pcb)
	struct atpcb *pcb;
{
	struct socket *so = pcb->atpcb_socket;

	/* Notify NBP that we are closing this DDP socket */
	if (pcb->lport) {
		ddp_notify_nbp(pcb->lport, pcb->pid, pcb->ddptype);
		pcb->lport = 0;
	}

	so->so_pcb = 0;
	so->so_flags |= SOF_PCBCLEARING;
	if ((pcb->atpcb_next) && (pcb->atpcb_prev))
	    remque((queue_t)pcb);
	zfree(atpcb_zone, pcb);
	sofree(so);
	return(0);
}

int ddp_socket_inuse(ddpsock, proto)
          u_char ddpsock, proto;
{
          struct atpcb *pcb;

	  if ((!proto || (proto == DDP_ATP)) && atp_inputQ[ddpsock])
	  	return TRUE;
          if ((!proto || (proto == DDP_ADSP)) && adsp_inputQ[ddpsock])
                return TRUE;
          if (ddp_handler[ddpsock].func)
                return TRUE;
          for (pcb = ddp_head.atpcb_next; pcb != &ddp_head;
	       pcb = pcb->atpcb_next) {
	  	if (pcb->lport == ddpsock &&
		    (!pcb->ddptype || !proto || (pcb->ddptype == proto)))
			return TRUE;
	  }
	  return FALSE;
}

int at_pcbbind(pcb, nam)
	register struct atpcb *pcb;
	struct sockaddr *nam;
{
	register struct socket *so = pcb->atpcb_socket;
	register struct sockaddr_at *local = (struct sockaddr_at *) nam;
	u_char ddpsock = local->sat_port;

	if ((!ifID_home) || (local->sat_family != AF_APPLETALK))
		return(EADDRNOTAVAIL);

	if (pcb->lport != ATADDR_ANYPORT ||
	    pcb->laddr.s_node != ATADDR_ANYNODE ||
	    pcb->laddr.s_net != ATADDR_ANYNET)
		return(EINVAL);

	/* Request for dynamic socket? */
	if (ddpsock == 0) {
		/* Search table for free one */
		/* *** borrow IP algorithm, instead? *** */
		for (ddpsock = DDP_SOCKET_LAST; 
		     ddpsock >= (DDP_SOCKET_1st_DYNAMIC + 1); 
		     				/* sip has 1st */
		     ddpsock--) {
			if (! ddp_socket_inuse(ddpsock, pcb->ddptype))
				break;
		}
		if (ddpsock < (DDP_SOCKET_1st_DYNAMIC + 1))
			return(EADDRNOTAVAIL);	/* Error if no free sockets */
	} else {
		/* Asking to open a socket by its number.  
		   Check if its legal & free. */
		if (ddpsock > DDP_SOCKET_LAST)
			return(EINVAL);
		if (ddp_socket_inuse(ddpsock, pcb->ddptype))
			return(EADDRNOTAVAIL);
	}

	pcb->lport = ddpsock;
	/* if address is specified, make sure address matches one of the 
	   interfaces configured for AppleTalk */
	if (local->sat_addr.s_net || local->sat_addr.s_node) {
	    if (MULTIHOME_MODE) {
		at_ifaddr_t *ifID;
		TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
			if (ifID->ifThisNode.s_net == local->sat_addr.s_net &&
			    ifID->ifThisNode.s_node == local->sat_addr.s_node) {
				pcb->laddr = local->sat_addr;
				return(0);
			}
		}
		return(EINVAL);
	    } else {
	      /* for single-port and router modes if the local address is
		 specified, it must match the default interface, which is
		 what will be put into packets' source address anyway */
		if (ifID_home->ifThisNode.s_net == local->sat_addr.s_net &&
		    ifID_home->ifThisNode.s_node == local->sat_addr.s_node) {
			pcb->laddr = local->sat_addr;
			return(0);
		}
		return(EINVAL);

	    }
	}
	return(0);
}
