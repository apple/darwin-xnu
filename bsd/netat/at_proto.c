/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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

/*	at_proto.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <kern/locks.h>

#include <sys/sysctl.h>

#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/at_var.h>
#include <netat/ddp.h>


/*
 * Dummy usrreqs struct created by Ted for FreeBSD 3.x integration. 
 * Fill in supported functions as appropriate.
 */
struct pr_usrreqs ddp_usrreqs = {
	ddp_pru_abort,  pru_accept_notsupp, ddp_pru_attach, ddp_pru_bind,
	ddp_pru_connect, pru_connect2_notsupp, ddp_pru_control, ddp_pru_detach,
	ddp_pru_disconnect, pru_listen_notsupp, ddp_pru_peeraddr, pru_rcvd_notsupp,
	pru_rcvoob_notsupp, ddp_pru_send, pru_sense_null, ddp_pru_shutdown,
	ddp_pru_sockaddr, sosend, soreceive, pru_sopoll_notsupp
};

extern struct domain atalkdomain;
extern void atalk_dominit(void);

struct protosw atalksw[] = {
  { SOCK_RAW,	&atalkdomain,	/*protocol*/ 0,	PR_ATOMIC|PR_ADDR,
    /*input*/ 0, /*output*/ 0, /*clinput*/ 0, ddp_ctloutput,
    /*ousrreq*/ 0, 
    ddp_init, /*fastto*/ 0, /*slowto*/ 0, /*drain*/ 0, 
    /*sysctl*/ 0, &ddp_usrreqs,
	0, 0, 0, /*lock, unlock, getlock */
   {0, 0}, 0, {0} /* filters */
  }
};

struct domain atalkdomain =
{ AF_APPLETALK,
  "appletalk",
  atalk_dominit,
  0,
  0, 
  atalksw,
  0,
  0, /* dom_rtattach */
  0, 0, /* dom_rtoffset, dom_maxrtkey */
  DDP_X_HDR_SIZE, 0,
  0, /* domain global mutex */
  0,  /* domain flags */
  {0, 0} /*reserved[2] */
};

struct domain * atalkdom = &atalkdomain;
lck_mtx_t  *atalk_mutex = NULL;

lck_mtx_t *atalk_cluster_lock = NULL;
static lck_attr_t *atalk_lock_attr;
static lck_grp_t *atalk_lock_grp;
static lck_grp_attr_t *atalk_lock_grp_attr;

static int at_saved_lock, at_saved_unlock;

SYSCTL_NODE(_net, PF_APPLETALK, appletalk, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "AppleTalk Family");

void
atalk_dominit(void)
{
	atalk_mutex = atalkdom->dom_mtx;

	atalk_lock_grp_attr = lck_grp_attr_alloc_init();
	atalk_lock_grp = lck_grp_alloc_init("appletalk", atalk_lock_grp_attr);
	atalk_lock_attr = lck_attr_alloc_init();
	atalk_cluster_lock = lck_mtx_alloc_init(atalk_lock_grp,
	    atalk_lock_attr);
}

void
atalk_lock()
{
	int lr_saved;
	lr_saved = (unsigned int) __builtin_return_address(0);

	lck_mtx_assert(atalkdom->dom_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(atalkdom->dom_mtx);
	at_saved_lock = lr_saved;
}
	
void
atalk_unlock()
{
	int lr_saved;
	lr_saved = (unsigned int) __builtin_return_address(0);

	lck_mtx_assert(atalkdom->dom_mtx, LCK_MTX_ASSERT_OWNED);
	at_saved_unlock = lr_saved;
	lck_mtx_unlock(atalkdom->dom_mtx);

}
	




