/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 *	Copyright (c) 1996-1998 Apple Computer, Inc.
 *	All Rights Reserved.
 */

/*    Modified for MP, 1996 by Tuyen Nguyen
 *    Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 */
#define ATP_DECLARE

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
#include <vm/vm_kern.h>         /* for kernel_map */

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/ddp.h>
#include <netat/at_pcb.h>
#include <netat/atp.h>
#include <netat/debug.h>

/*
 *	The init routine creates all the free lists
 *	Version 1.4 of atp_open.c on 89/02/09 17:53:11
 */

int atp_inited = 0;
struct atp_rcb_qhead atp_need_rel;
atlock_t atpall_lock;
atlock_t atptmo_lock;
atlock_t atpgen_lock;

/**********/
int atp_pidM[256];
gref_t *atp_inputQ[256];
struct atp_state *atp_used_list;

int atp_input(mp)
	gbuf_t *mp;
{
	register gref_t *gref;

	switch (gbuf_type(mp)) {
	case MSG_DATA:
		gref = atp_inputQ[((at_ddp_t *)gbuf_rptr(mp))->dst_socket];
		if ((gref == 0) || (gref == (gref_t *)1)) {
			dPrintf(D_M_ATP, D_L_WARNING, ("atp_input: no socket, skt=%d\n",
				((at_ddp_t *)gbuf_rptr(mp))->dst_socket));
			gbuf_freem(mp);
			return 0;
		}
		break;

	case MSG_IOCACK:
	case MSG_IOCNAK:
		gref = (gref_t *)((ioc_t *)gbuf_rptr(mp))->ioc_private;
		break;

	case MSG_IOCTL:
	default:
		dPrintf(D_M_ATP, D_L_WARNING, ("atp_input: unknown msg, type=%d\n",
			gbuf_type(mp)));
		gbuf_freem(mp);
		return 0;
	}

	atp_rput(gref, mp);
	return 0;
}

/**********/
void atp_init()
{
  int i;

  if (!atp_inited) {
	atp_inited = 1;
	atp_used_list = 0;
	atp_trans_abort.head = NULL;
	atp_trans_abort.tail = NULL;
		
	atp_need_rel.head = NULL;
	atp_need_rel.tail = NULL;

	bzero(atp_inputQ, sizeof(atp_inputQ));
	bzero(atp_pidM, sizeof(atp_pidM));
	asp_init();
  }
}

/*
 *	The open routine allocates a state structure
 */

/*ARGSUSED*/
int atp_open(gref, flag)
	gref_t *gref;
	int flag;
{
	register struct atp_state *atp;
	register int s, i;
	vm_offset_t	temp;
	
	/*
	 * Allocate and init state and reply control block lists
	 * if this is the first open
	 */
	if (atp_rcb_data == NULL) {
		if (kmem_alloc(kernel_map, &temp, sizeof(struct atp_rcb) * NATP_RCB) != KERN_SUCCESS) 
			return(ENOMEM);
		if (atp_rcb_data == NULL) {						
		        bzero((caddr_t)temp, sizeof(struct atp_rcb) * NATP_RCB);
			atp_rcb_data = (struct atp_rcb*)temp;					
			for (i = 0; i < NATP_RCB; i++) {
				atp_rcb_data[i].rc_list.next = atp_rcb_free_list;
				atp_rcb_free_list = &atp_rcb_data[i];
			}
		} else
			kmem_free(kernel_map, temp, sizeof(struct atp_rcb) * NATP_RCB);	/* already allocated by another process */	
	}
	
	if (atp_state_data == NULL) {
		if (kmem_alloc(kernel_map, &temp, sizeof(struct atp_state) * NATP_STATE) != KERN_SUCCESS) 
			return(ENOMEM);
		if (atp_state_data == NULL) {
		  bzero((caddr_t)temp, sizeof(struct atp_state) * NATP_STATE);
		        atp_state_data = (struct atp_state*) temp;
			for (i = 0; i < NATP_STATE; i++) {
				atp_state_data[i].atp_trans_waiting = atp_free_list;
				atp_free_list = &atp_state_data[i];
			}
		} else
			kmem_free(kernel_map, temp, sizeof(struct atp_state) * NATP_STATE);	
	}


	/*
	 *	If no atp structure available return failure
	 */

	ATDISABLE(s, atpall_lock);
	if ((atp = atp_free_list) == NULL) {
		ATENABLE(s, atpall_lock);
		return(EAGAIN);
	}

	/*
	 *	Update free list
	 */

	atp_free_list = atp->atp_trans_waiting;
	ATENABLE(s, atpall_lock);

	/*
	 *	Initialize the data structure
	 */

	atp->dflag = 0;
	atp->atp_trans_wait.head = NULL;
	atp->atp_trans_waiting = NULL;
	atp->atp_gref = gref;
	atp->atp_retry = 10;
	atp->atp_timeout = HZ/8;
	atp->atp_rcb_waiting = NULL;
	atp->atp_rcb.head = NULL;	
	atp->atp_flags = T_MPSAFE;
	atp->atp_socket_no = -1;
	atp->atp_pid = gref->pid;
	atp->atp_msgq = 0;
	ATLOCKINIT(atp->atp_lock);
	ATLOCKINIT(atp->atp_delay_lock);
	ATEVENTINIT(atp->atp_event);
	ATEVENTINIT(atp->atp_delay_event);
	gref->info = (void *)atp;

	/*
	 *	Return success
	 */

	if (flag) {
		ATDISABLE(s, atpall_lock);
		if ((atp->atp_trans_waiting = atp_used_list) != 0)
			atp->atp_trans_waiting->atp_rcb_waiting = atp;
		atp_used_list = atp;
		ATENABLE(s, atpall_lock);
	}
	return(0);
}

/*
 *	The close routine frees all the data structures
 */

/*ARGSUSED*/
int atp_close(gref, flag)
	gref_t *gref;
	int flag;
{
	extern void atp_req_timeout();
	register struct atp_state *atp;
	register struct atp_trans *trp;
	register struct atp_rcb *rcbp;
	register int s;
	int socket;
	pid_t pid;

	atp = (struct atp_state *)gref->info;
	if (atp->dflag)
		atp = (struct atp_state *)atp->atp_msgq;
	if (atp->atp_msgq) {
		gbuf_freem(atp->atp_msgq);
		atp->atp_msgq = 0;
	}

	ATDISABLE(s, atp->atp_lock);
	atp->atp_flags |= ATP_CLOSING;
	socket = atp->atp_socket_no;
	if (socket != -1)
		atp_inputQ[socket] = (gref_t *)1;

	/*
	 * blow away all pending timers
	 */
	for (trp = atp->atp_trans_wait.head; trp; trp = trp->tr_list.next)
		atp_untimout(atp_req_timeout, trp);

	/*
	 *	Release pending transactions + rcbs
	 */
	while ((trp = atp->atp_trans_wait.head))
		atp_free(trp);
	while ((rcbp = atp->atp_rcb.head))
		atp_rcb_free(rcbp);
	while ((rcbp = atp->atp_attached.head))
		atp_rcb_free(rcbp);
	ATENABLE(s, atp->atp_lock);

	if (flag && (socket == -1))
		atp_dequeue_atp(atp);

	/*
	 *	free the state variable
	 */
	ATDISABLE(s, atpall_lock);
	atp->atp_socket_no = -1;
	atp->atp_trans_waiting = atp_free_list;
	atp_free_list = atp;
	ATENABLE(s, atpall_lock);

	if (socket != -1) {
		pid = (pid_t)atp_pidM[socket];
		atp_pidM[socket] = 0;
		atp_inputQ[socket] = NULL;
		if (pid)
		    ddp_notify_nbp(socket, pid, DDP_ATP);
	}

	return 0;
}
