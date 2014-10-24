/*
 * Copyright (c) 2002-2012 Apple Inc. All rights reserved.
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
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/queue.h>


#include "hfs.h"	/* XXX bringup */
#include "hfs_cnode.h"

extern lck_attr_t *  hfs_lock_attr;
extern lck_grp_t *  hfs_mutex_group;
extern lck_grp_t *  hfs_rwlock_group;

lck_grp_t * chash_lck_grp;
lck_grp_attr_t * chash_lck_grp_attr;
lck_attr_t * chash_lck_attr;


#define CNODEHASH(hfsmp, inum) (&hfsmp->hfs_cnodehashtbl[(inum) & hfsmp->hfs_cnodehash])


/*
 * Initialize cnode hash table.
 */
__private_extern__
void
hfs_chashinit()
{
	chash_lck_grp_attr= lck_grp_attr_alloc_init();
	chash_lck_grp  = lck_grp_alloc_init("cnode_hash", chash_lck_grp_attr);
	chash_lck_attr = lck_attr_alloc_init();
}

static void hfs_chash_lock(struct hfsmount *hfsmp) 
{
	lck_mtx_lock(&hfsmp->hfs_chash_mutex);
}

static void hfs_chash_lock_spin(struct hfsmount *hfsmp) 
{
	lck_mtx_lock_spin(&hfsmp->hfs_chash_mutex);
}

static void hfs_chash_lock_convert (__unused struct hfsmount *hfsmp)
{
	lck_mtx_convert_spin(&hfsmp->hfs_chash_mutex);
}

static void hfs_chash_unlock(struct hfsmount *hfsmp) 
{
	lck_mtx_unlock(&hfsmp->hfs_chash_mutex);
}

__private_extern__
void
hfs_chashinit_finish(struct hfsmount *hfsmp)
{
	lck_mtx_init(&hfsmp->hfs_chash_mutex, chash_lck_grp, chash_lck_attr);

	hfsmp->hfs_cnodehashtbl = hashinit(desiredvnodes / 4, M_HFSMNT, &hfsmp->hfs_cnodehash);
}

__private_extern__
void
hfs_delete_chash(struct hfsmount *hfsmp)
{
	lck_mtx_destroy(&hfsmp->hfs_chash_mutex, chash_lck_grp);

	FREE(hfsmp->hfs_cnodehashtbl, M_HFSMNT);
}


/*
 * Use the device, inum pair to find the incore cnode.
 *
 * If it is in core, but locked, wait for it.
 */
struct vnode *
hfs_chash_getvnode(struct hfsmount *hfsmp, ino_t inum, int wantrsrc, int skiplock, int allow_deleted)
{
	struct cnode *cp;
	struct vnode *vp;
	int error;
	u_int32_t vid;

	/* 
	 * Go through the hash list
	 * If a cnode is in the process of being cleaned out or being
	 * allocated, wait for it to be finished and then try again.
	 */
loop:
	hfs_chash_lock_spin(hfsmp);

	for (cp = CNODEHASH(hfsmp, inum)->lh_first; cp; cp = cp->c_hash.le_next) {
		if (cp->c_fileid != inum)
			continue;
		/* Wait if cnode is being created or reclaimed. */
		if (ISSET(cp->c_hflag, H_ALLOC | H_TRANSIT | H_ATTACH)) {
		        SET(cp->c_hflag, H_WAITING);

			(void) msleep(cp, &hfsmp->hfs_chash_mutex, PDROP | PINOD,
			              "hfs_chash_getvnode", 0);
			goto loop;
		}
		/* Obtain the desired vnode. */
		vp = wantrsrc ? cp->c_rsrc_vp : cp->c_vp;
		if (vp == NULLVP)
			goto exit;

		vid = vnode_vid(vp);
		hfs_chash_unlock(hfsmp);

		if ((error = vnode_getwithvid(vp, vid))) {
		        /*
			 * If vnode is being reclaimed, or has
			 * already changed identity, no need to wait
			 */
		        return (NULL);
		}
		if (!skiplock && hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) != 0) {
			vnode_put(vp);
			return (NULL);
		}

		/*
		 * Skip cnodes that are not in the name space anymore
		 * we need to check with the cnode lock held because
		 * we may have blocked acquiring the vnode ref or the
		 * lock on the cnode which would allow the node to be
		 * unlinked
		 */
		if (!allow_deleted) {
			if (cp->c_flag & (C_NOEXISTS | C_DELETED)) {
				if (!skiplock) {
					hfs_unlock(cp);
				}
				vnode_put(vp);
				return (NULL);
			}			
		}
		return (vp);
	}
exit:
	hfs_chash_unlock(hfsmp);
	return (NULL);
}


/*
 * Use the device, fileid pair to snoop an incore cnode.
 *
 * A cnode can exists in chash even after it has been 
 * deleted from the catalog, so this function returns 
 * ENOENT if C_NOEXIST is set in the cnode's flag.
 * 
 */
int
hfs_chash_snoop(struct hfsmount *hfsmp, ino_t inum, int existence_only, 
				int (*callout)(const cnode_t *cp, void *), void * arg)
{
	struct cnode *cp;
	int result = ENOENT;

	/* 
	 * Go through the hash list
	 * If a cnode is in the process of being cleaned out or being
	 * allocated, wait for it to be finished and then try again.
	 */
	hfs_chash_lock(hfsmp);

	for (cp = CNODEHASH(hfsmp, inum)->lh_first; cp; cp = cp->c_hash.le_next) {
		if (cp->c_fileid != inum)
			continue;
	
		/*
		 * Under normal circumstances, we would want to return ENOENT if a cnode is in
		 * the hash and it is marked C_NOEXISTS or C_DELETED.  However, if the CNID
		 * namespace has wrapped around, then we have the possibility of collisions.  
		 * In that case, we may use this function to validate whether or not we 
		 * should trust the nextCNID value in the hfs mount point.  
		 * 
		 * If we didn't do this, then it would be possible for a cnode that is no longer backed
		 * by anything on-disk (C_NOEXISTS) to still exist in the hash along with its
		 * vnode.  The cat_create routine could then create a new entry in the catalog
		 * re-using that CNID.  Then subsequent hfs_getnewvnode calls will repeatedly fail
		 * trying to look it up/validate it because it is marked C_NOEXISTS.  So we want
		 * to prevent that from happening as much as possible.
		 */
		if (existence_only) {
			result = 0;
			break;
		}

		/* Skip cnodes that have been removed from the catalog */
		if (cp->c_flag & (C_NOEXISTS | C_DELETED)) {
			result = EACCES;
			break;
		}

		/* Skip cnodes being created or reclaimed. */
		if (!ISSET(cp->c_hflag, H_ALLOC | H_TRANSIT | H_ATTACH)) {
			result = callout(cp, arg);
		}
		break;
	}
	hfs_chash_unlock(hfsmp);

	return (result);
}


/*
 * Use the device, fileid pair to find the incore cnode.
 * If no cnode if found one is created
 *
 * If it is in core, but locked, wait for it.
 *
 * If the cnode is C_DELETED, then return NULL since that 
 * inum is no longer valid for lookups (open-unlinked file).
 *
 * If the cnode is C_DELETED but also marked C_RENAMED, then that means
 * the cnode was renamed over and a new entry exists in its place.  The caller
 * should re-drive the lookup to get the newer entry.  In that case, we'll still
 * return NULL for the cnode, but also return GNV_CHASH_RENAMED in the output flags
 * of this function to indicate the caller that they should re-drive.
 */
struct cnode *
hfs_chash_getcnode(struct hfsmount *hfsmp, ino_t inum, struct vnode **vpp, 
				   int wantrsrc, int skiplock, int *out_flags, int *hflags)
{
	struct cnode	*cp;
	struct cnode	*ncp = NULL;
	vnode_t		vp;
	u_int32_t	vid;

	/* 
	 * Go through the hash list
	 * If a cnode is in the process of being cleaned out or being
	 * allocated, wait for it to be finished and then try again.
	 */
loop:
	hfs_chash_lock_spin(hfsmp);

loop_with_lock:
	for (cp = CNODEHASH(hfsmp, inum)->lh_first; cp; cp = cp->c_hash.le_next) {
		if (cp->c_fileid != inum)
			continue;
		/*
		 * Wait if cnode is being created, attached to or reclaimed.
		 */
		if (ISSET(cp->c_hflag, H_ALLOC | H_ATTACH | H_TRANSIT)) {
		        SET(cp->c_hflag, H_WAITING);

			(void) msleep(cp, &hfsmp->hfs_chash_mutex, PINOD,
			              "hfs_chash_getcnode", 0);
			goto loop_with_lock;
		}
		vp = wantrsrc ? cp->c_rsrc_vp : cp->c_vp;
		if (vp == NULL) {
			/*
			 * The desired vnode isn't there so tag the cnode.
			 */
			SET(cp->c_hflag, H_ATTACH);
			*hflags |= H_ATTACH;

			hfs_chash_unlock(hfsmp);
		} else {
			vid = vnode_vid(vp);

			hfs_chash_unlock(hfsmp);

			if (vnode_getwithvid(vp, vid))
		        	goto loop;
		}
		if (ncp) {
			/*
			 * someone else won the race to create
			 * this cnode and add it to the hash
			 * just dump our allocation
			 */
			FREE_ZONE(ncp, sizeof(struct cnode), M_HFSNODE);
			ncp = NULL;
		}

		if (!skiplock) {
			hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
		}

		/*
		 * Skip cnodes that are not in the name space anymore
		 * we need to check with the cnode lock held because
		 * we may have blocked acquiring the vnode ref or the
		 * lock on the cnode which would allow the node to be
		 * unlinked.
		 *
		 * Don't return a cnode in this case since the inum
		 * is no longer valid for lookups.
		 */
		if ((cp->c_flag & (C_NOEXISTS | C_DELETED)) && !wantrsrc) {
			int renamed = 0;
			if (cp->c_flag & C_RENAMED) {
				renamed = 1;
			}
			if (!skiplock)
				hfs_unlock(cp);
			if (vp != NULLVP) {
				vnode_put(vp);
			} else {
				hfs_chash_lock_spin(hfsmp);
				CLR(cp->c_hflag, H_ATTACH);
				*hflags &= ~H_ATTACH;
				if (ISSET(cp->c_hflag, H_WAITING)) {
					CLR(cp->c_hflag, H_WAITING);
					wakeup((caddr_t)cp);
				}
				hfs_chash_unlock(hfsmp);
			}
			vp = NULL;
			cp = NULL;
			if (renamed) {
				*out_flags = GNV_CHASH_RENAMED;
			}
		}
		*vpp = vp;
		return (cp);
	}

	/* 
	 * Allocate a new cnode
	 */
	if (skiplock && !wantrsrc)
		panic("%s - should never get here when skiplock is set \n", __FUNCTION__);

	if (ncp == NULL) {
		hfs_chash_unlock(hfsmp);

	        MALLOC_ZONE(ncp, struct cnode *, sizeof(struct cnode), M_HFSNODE, M_WAITOK);
		/*
		 * since we dropped the chash lock, 
		 * we need to go back and re-verify
		 * that this node hasn't come into 
		 * existence...
		 */
		goto loop;
	}
	hfs_chash_lock_convert(hfsmp);

	bzero(ncp, sizeof(struct cnode));
	SET(ncp->c_hflag, H_ALLOC);
	*hflags |= H_ALLOC;
	ncp->c_fileid = inum;
	TAILQ_INIT(&ncp->c_hintlist); /* make the list empty */
	TAILQ_INIT(&ncp->c_originlist);

	lck_rw_init(&ncp->c_rwlock, hfs_rwlock_group, hfs_lock_attr);
	if (!skiplock)
		(void) hfs_lock(ncp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);

	/* Insert the new cnode with it's H_ALLOC flag set */
	LIST_INSERT_HEAD(CNODEHASH(hfsmp, inum), ncp, c_hash);
	hfs_chash_unlock(hfsmp);

	*vpp = NULL;
	return (ncp);
}


__private_extern__
void
hfs_chashwakeup(struct hfsmount *hfsmp, struct cnode *cp, int hflags)
{
	hfs_chash_lock_spin(hfsmp);

	CLR(cp->c_hflag, hflags);

	if (ISSET(cp->c_hflag, H_WAITING)) {
	        CLR(cp->c_hflag, H_WAITING);
		wakeup((caddr_t)cp);
	}
	hfs_chash_unlock(hfsmp);
}


/*
 * Re-hash two cnodes in the hash table.
 */
__private_extern__
void
hfs_chash_rehash(struct hfsmount *hfsmp, struct cnode *cp1, struct cnode *cp2)
{
	hfs_chash_lock_spin(hfsmp);

	LIST_REMOVE(cp1, c_hash);
	LIST_REMOVE(cp2, c_hash);
	LIST_INSERT_HEAD(CNODEHASH(hfsmp, cp1->c_fileid), cp1, c_hash);
	LIST_INSERT_HEAD(CNODEHASH(hfsmp, cp2->c_fileid), cp2, c_hash);

	hfs_chash_unlock(hfsmp);
}


/*
 * Remove a cnode from the hash table.
 */
__private_extern__
int
hfs_chashremove(struct hfsmount *hfsmp, struct cnode *cp)
{
	hfs_chash_lock_spin(hfsmp);

	/* Check if a vnode is getting attached */
	if (ISSET(cp->c_hflag, H_ATTACH)) {
		hfs_chash_unlock(hfsmp);
		return (EBUSY);
	}
	if (cp->c_hash.le_next || cp->c_hash.le_prev) {
	    LIST_REMOVE(cp, c_hash);
	    cp->c_hash.le_next = NULL;
	    cp->c_hash.le_prev = NULL;
	}
	hfs_chash_unlock(hfsmp);

	return (0);
}

/*
 * Remove a cnode from the hash table and wakeup any waiters.
 */
__private_extern__
void
hfs_chash_abort(struct hfsmount *hfsmp, struct cnode *cp)
{
	hfs_chash_lock_spin(hfsmp);

	LIST_REMOVE(cp, c_hash);
	cp->c_hash.le_next = NULL;
	cp->c_hash.le_prev = NULL;

	CLR(cp->c_hflag, H_ATTACH | H_ALLOC);
	if (ISSET(cp->c_hflag, H_WAITING)) {
	        CLR(cp->c_hflag, H_WAITING);
		wakeup((caddr_t)cp);
	}
	hfs_chash_unlock(hfsmp);
}


/*
 * mark a cnode as in transition
 */
__private_extern__
void
hfs_chash_mark_in_transit(struct hfsmount *hfsmp, struct cnode *cp)
{
	hfs_chash_lock_spin(hfsmp);

        SET(cp->c_hflag, H_TRANSIT);

	hfs_chash_unlock(hfsmp);
}

/* Search a cnode in the hash.  This function does not return cnode which 
 * are getting created, destroyed or in transition.  Note that this function
 * does not acquire the cnode hash mutex, and expects the caller to acquire it.
 * On success, returns pointer to the cnode found.  On failure, returns NULL.
 */
static 
struct cnode *
hfs_chash_search_cnid(struct hfsmount *hfsmp, cnid_t cnid) 
{
	struct cnode *cp;

	for (cp = CNODEHASH(hfsmp, cnid)->lh_first; cp; cp = cp->c_hash.le_next) {
		if (cp->c_fileid == cnid) {
			break;
		}
	}

	/* If cnode is being created or reclaimed, return error. */
	if (cp && ISSET(cp->c_hflag, H_ALLOC | H_TRANSIT | H_ATTACH)) {
		cp = NULL;
	}

	return cp;
}

/* Search a cnode corresponding to given device and ID in the hash.  If the 
 * found cnode has kHFSHasChildLinkBit cleared, set it.  If the cnode is not 
 * found, no new cnode is created and error is returned.
 * 
 * Return values - 
 *	-1 : The cnode was not found.
 * 	 0 : The cnode was found, and the kHFSHasChildLinkBit was already set.
 *	 1 : The cnode was found, the kHFSHasChildLinkBit was not set, and the 
 *	     function had to set that bit.
 */
__private_extern__ 
int
hfs_chash_set_childlinkbit(struct hfsmount *hfsmp, cnid_t cnid)
{
	int retval = -1;
	struct cnode *cp;

	hfs_chash_lock_spin(hfsmp);

	cp = hfs_chash_search_cnid(hfsmp, cnid);
	if (cp) {
		if (cp->c_attr.ca_recflags & kHFSHasChildLinkMask) {
			retval = 0;
		} else {
			cp->c_attr.ca_recflags |= kHFSHasChildLinkMask;
			retval = 1;
		}
	}
	hfs_chash_unlock(hfsmp);

	return retval;
}
