/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1991, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	  must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *	  may be used to endorse or promote products derived from this software
 *	  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)hfs_chash.c
 *	derived from @(#)ufs_ihash.c	8.7 (Berkeley) 5/17/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/queue.h>

#include "hfs_cnode.h"


/*
 * Structures associated with cnode caching.
 */
LIST_HEAD(cnodehashhead, cnode) *cnodehashtbl;
u_long	cnodehash;		/* size of hash table - 1 */
#define CNODEHASH(device, inum) (&cnodehashtbl[((device) + (inum)) & cnodehash])
struct slock hfs_chash_slock;

/*
 * Initialize cnode hash table.
 */
__private_extern__
void
hfs_chashinit()
{
	cnodehashtbl = hashinit(desiredvnodes, M_HFSMNT, &cnodehash);
	simple_lock_init(&hfs_chash_slock);
}


/*
 * Use the device, inum pair to find the incore cnode.
 *
 * If it is in core, but locked, wait for it.
 *
 * If the requested vnode (fork) is not available, then
 * take a reference on the other vnode (fork) so that
 * the upcoming getnewvnode can not aquire it.
 */
__private_extern__
struct cnode *
hfs_chashget(dev_t dev, ino_t inum, int wantrsrc,
		struct vnode **vpp, struct vnode **rvpp)
{
	struct proc *p = current_proc();
	struct cnode *cp;
	struct vnode *vp;
	int error;

	*vpp = NULLVP;
	*rvpp = NULLVP;
	/* 
	 * Go through the hash list
	 * If a cnode is in the process of being cleaned out or being
	 * allocated, wait for it to be finished and then try again.
	 */
loop:
	simple_lock(&hfs_chash_slock);
	for (cp = CNODEHASH(dev, inum)->lh_first; cp; cp = cp->c_hash.le_next) {
		if ((cp->c_fileid != inum) || (cp->c_dev != dev))
			continue;
		if (ISSET(cp->c_flag, C_ALLOC)) {
			/*
			 * cnode is being created. Wait for it to finish.
			 */
			SET(cp->c_flag, C_WALLOC);
			simple_unlock(&hfs_chash_slock);
			(void) tsleep((caddr_t)cp, PINOD, "hfs_chashget-1", 0);
			goto loop;
		}	
		if (ISSET(cp->c_flag, C_TRANSIT)) {
			/*
			 * cnode is getting reclaimed wait for
			 * the operation to complete and return
			 * error
			 */
			SET(cp->c_flag, C_WTRANSIT);
			simple_unlock(&hfs_chash_slock);
			(void)tsleep((caddr_t)cp, PINOD, "hfs_chashget-2", 0);
			goto loop;
		}
		if (cp->c_flag & C_NOEXISTS)
			continue;

		/*
		 * Try getting the desired vnode first.  If
		 * it isn't available then take a reference
		 * on the other vnode.
		 */
		vp = wantrsrc ? cp->c_rsrc_vp : cp->c_vp;
		if (vp == NULLVP)
			vp = wantrsrc ? cp->c_vp : cp->c_rsrc_vp;
		if (vp == NULLVP)
			panic("hfs_chashget: orphaned cnode in hash");

		simple_lock(&vp->v_interlock);
		simple_unlock(&hfs_chash_slock);
		if (vget(vp, LK_EXCLUSIVE | LK_INTERLOCK, p))
			goto loop;
		else if (cp->c_flag & C_NOEXISTS) {
			/*
			 * While we were blocked the cnode got deleted.
			 */
			vput(vp);
			goto loop;
		}

		if (VNODE_IS_RSRC(vp))
			*rvpp = vp;
		else
			*vpp = vp;
		/*
		 * Note that vget can block before aquiring the
		 * cnode lock.  So we need to check if the vnode
		 * we wanted was created while we blocked.
		 */
		if (wantrsrc && *rvpp == NULL && cp->c_rsrc_vp) {
			error = vget(cp->c_rsrc_vp, 0, p);
			vput(*vpp);	/* ref no longer needed */
			*vpp = NULL;
			if (error)
				goto loop;
			*rvpp = cp->c_rsrc_vp;

		} else if (!wantrsrc && *vpp == NULL && cp->c_vp) {
			error = vget(cp->c_vp, 0, p);
			vput(*rvpp);	/* ref no longer needed */
			*rvpp = NULL;
			if (error)
				goto loop;
			*vpp = cp->c_vp;
		}
		return (cp);
	}
	simple_unlock(&hfs_chash_slock);
	return (NULL);
}


/*
 * Insert a cnode into the hash table.
 */
__private_extern__
void
hfs_chashinsert(struct cnode *cp)
{
	if (cp->c_fileid == 0)
		panic("hfs_chashinsert: trying to insert file id 0");
	simple_lock(&hfs_chash_slock);
	LIST_INSERT_HEAD(CNODEHASH(cp->c_dev, cp->c_fileid), cp, c_hash);
	simple_unlock(&hfs_chash_slock);
}


/*
 * Remove a cnode from the hash table.
 */
__private_extern__
void
hfs_chashremove(struct cnode *cp)
{
	simple_lock(&hfs_chash_slock);
	LIST_REMOVE(cp, c_hash);
	cp->c_hash.le_next = NULL;
	cp->c_hash.le_prev = NULL;
	simple_unlock(&hfs_chash_slock);
}

