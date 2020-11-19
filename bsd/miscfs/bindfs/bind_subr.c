/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

/*-
 * Portions Copyright (c) 1992, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 *  @(#)null_subr.c 8.7 (Berkeley) 5/14/95
 *
 * $FreeBSD$
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include "bindfs.h"

/*
 * Null layer cache:
 * Each cache entry holds a reference to the lower vnode
 * along with a pointer to the alias vnode.  When an
 * entry is added the lower vnode is VREF'd.  When the
 * alias is removed the lower vnode is vrele'd.
 */

#define BIND_HASH_SIZE (desiredvnodes / 10)

/* xnu doesn't really have the functionality freebsd uses here..gonna try this
 * hacked hash...*/
#define BIND_NHASH(vp) (&bind_node_hashtbl[((((uintptr_t)vp) >> vnsz2log) + (uintptr_t)vnode_mount(vp)) & bind_hash_mask])

static LIST_HEAD(bind_node_hashhead, bind_node) * bind_node_hashtbl;
static lck_mtx_t bind_hashmtx;
static lck_attr_t * bind_hashlck_attr;
static lck_grp_t * bind_hashlck_grp;
static lck_grp_attr_t * bind_hashlck_grp_attr;
static u_long bind_hash_mask;

/*  xnu doesn't have hashes built into vnodes. This mimics what freebsd does
 *  9 is an eyeball of the log 2 size of vnode */
static int vnsz2log = 9;

static int bind_hashins(struct mount *, struct bind_node *, struct vnode **);

int
bindfs_init_lck(lck_mtx_t * lck)
{
	int error = 1;
	if (lck && bind_hashlck_grp && bind_hashlck_attr) {
		lck_mtx_init(lck, bind_hashlck_grp, bind_hashlck_attr);
		error = 0;
	}
	return error;
}

int
bindfs_destroy_lck(lck_mtx_t * lck)
{
	int error = 1;
	if (lck && bind_hashlck_grp) {
		lck_mtx_destroy(lck, bind_hashlck_grp);
		error = 0;
	}
	return error;
}

/*
 * Initialise cache headers
 */
int
bindfs_init(__unused struct vfsconf * vfsp)
{
	BINDFSDEBUG("%s\n", __FUNCTION__);

	/* assuming for now that this happens immediately and by default after fs
	 * installation */
	bind_hashlck_grp_attr = lck_grp_attr_alloc_init();
	if (bind_hashlck_grp_attr == NULL) {
		goto error;
	}
	bind_hashlck_grp = lck_grp_alloc_init("com.apple.filesystems.bindfs", bind_hashlck_grp_attr);
	if (bind_hashlck_grp == NULL) {
		goto error;
	}
	bind_hashlck_attr = lck_attr_alloc_init();
	if (bind_hashlck_attr == NULL) {
		goto error;
	}

	bind_node_hashtbl = hashinit(BIND_HASH_SIZE, M_TEMP, &bind_hash_mask);
	if (bind_node_hashtbl == NULL) {
		goto error;
	}
	lck_mtx_init(&bind_hashmtx, bind_hashlck_grp, bind_hashlck_attr);

	BINDFSDEBUG("%s finished\n", __FUNCTION__);
	return 0;
error:
	printf("BINDFS: failed to initialize globals\n");
	if (bind_hashlck_grp_attr) {
		lck_grp_attr_free(bind_hashlck_grp_attr);
		bind_hashlck_grp_attr = NULL;
	}
	if (bind_hashlck_grp) {
		lck_grp_free(bind_hashlck_grp);
		bind_hashlck_grp = NULL;
	}
	if (bind_hashlck_attr) {
		lck_attr_free(bind_hashlck_attr);
		bind_hashlck_attr = NULL;
	}
	return KERN_FAILURE;
}

int
bindfs_destroy(void)
{
	/* This gets called when the fs is uninstalled, there wasn't an exact
	 * equivalent in vfsops */
	lck_mtx_destroy(&bind_hashmtx, bind_hashlck_grp);
	hashdestroy(bind_node_hashtbl, M_TEMP, bind_hash_mask);
	if (bind_hashlck_grp_attr) {
		lck_grp_attr_free(bind_hashlck_grp_attr);
		bind_hashlck_grp_attr = NULL;
	}
	if (bind_hashlck_grp) {
		lck_grp_free(bind_hashlck_grp);
		bind_hashlck_grp = NULL;
	}
	if (bind_hashlck_attr) {
		lck_attr_free(bind_hashlck_attr);
		bind_hashlck_attr = NULL;
	}
	return 0;
}

/*
 * Find the bindfs vnode mapped to lowervp. Return it in *vpp with an iocount if found.
 * Return 0 on success. On failure *vpp will be NULL and a non-zero error code will be returned.
 */
int
bind_hashget(struct mount * mp, struct vnode * lowervp, struct vnode ** vpp)
{
	struct bind_node_hashhead * hd;
	struct bind_node * a;
	struct vnode * vp = NULL;
	int error = ENOENT;

	/*
	 * Find hash base, and then search the (two-way) linked
	 * list looking for a bind_node structure which is referencing
	 * the lower vnode. We only give up our reference at reclaim so
	 * just check whether the lowervp has gotten pulled from under us
	 */
	hd = BIND_NHASH(lowervp);
	lck_mtx_lock(&bind_hashmtx);
	LIST_FOREACH(a, hd, bind_hash)
	{
		if (a->bind_lowervp == lowervp && vnode_mount(BINDTOV(a)) == mp) {
			vp = BINDTOV(a);
			if (a->bind_lowervid != vnode_vid(lowervp)) {
				/*lowervp has reved */
				error = EIO;
				vp = NULL;
			}
			break;
		}
	}
	lck_mtx_unlock(&bind_hashmtx);

	if (vp != NULL) {
		error = vnode_getwithvid(vp, a->bind_myvid);
		if (error == 0) {
			*vpp = vp;
		}
	}
	return error;
}

/*
 * Act like bind_hashget, but add passed bind_node to hash if no existing
 * node found.
 * If we find a vnode in the hash table it is returned via vpp. If we don't
 * find a hit in the table, then vpp is NULL on return and xp is added to the table.
 * 0 is returned if a hash table hit occurs or if we insert the bind_node.
 * EIO is returned if we found a hash table hit but the lower vnode was recycled.
 */
static int
bind_hashins(struct mount * mp, struct bind_node * xp, struct vnode ** vpp)
{
	struct bind_node_hashhead * hd;
	struct bind_node * oxp;
	struct vnode * ovp = NULL;
	int error = 0;

	hd = BIND_NHASH(xp->bind_lowervp);
	lck_mtx_lock(&bind_hashmtx);
	LIST_FOREACH(oxp, hd, bind_hash)
	{
		if (oxp->bind_lowervp == xp->bind_lowervp && vnode_mount(BINDTOV(oxp)) == mp) {
			ovp = BINDTOV(oxp);
			if (oxp->bind_lowervid != vnode_vid(oxp->bind_lowervp)) {
				/*	vp doesn't exist so return null (not sure we are actually gonna catch
				 *  recycle right now
				 *  This is an exceptional case right now, it suggests the vnode we are
				 *  trying to add has been recycled
				 *  don't add it.*/
				error = EIO;
				ovp = NULL;
			}
			goto end;
		}
	}
	/* if it wasn't in the hash map then the vnode pointed to by xp already has a
	 * iocount so don't get another. */
	LIST_INSERT_HEAD(hd, xp, bind_hash);
	xp->bind_flags |= BIND_FLAG_HASHED;
end:
	lck_mtx_unlock(&bind_hashmtx);
	if (ovp != NULL) {
		/* if we found something in the hash map then grab an iocount */
		error = vnode_getwithvid(ovp, oxp->bind_myvid);
		if (error == 0) {
			*vpp = ovp;
		}
	}
	return error;
}

/*
 * Remove node from hash.
 */
void
bind_hashrem(struct bind_node * xp)
{
	if (xp->bind_flags & BIND_FLAG_HASHED) {
		lck_mtx_lock(&bind_hashmtx);
		LIST_REMOVE(xp, bind_hash);
		lck_mtx_unlock(&bind_hashmtx);
	}
}

static struct bind_node *
bind_nodecreate(struct vnode * lowervp)
{
	struct bind_node * xp;

	MALLOC(xp, struct bind_node *, sizeof(struct bind_node), M_TEMP, M_WAITOK | M_ZERO);
	if (xp != NULL) {
		if (lowervp) {
			xp->bind_lowervp  = lowervp;
			xp->bind_lowervid = vnode_vid(lowervp);
		}
	}
	return xp;
}

/* assumption is that vnode has iocount on it after vnode create */
int
bind_getnewvnode(
	struct mount * mp, struct vnode * lowervp, struct vnode * dvp, struct vnode ** vpp, struct componentname * cnp, int root)
{
	struct vnode_fsparam vnfs_param;
	int error             = 0;
	enum vtype type       = VDIR;
	struct bind_node * xp = bind_nodecreate(lowervp);

	if (xp == NULL) {
		return ENOMEM;
	}

	if (lowervp) {
		type = vnode_vtype(lowervp);
	}

	vnfs_param.vnfs_mp         = mp;
	vnfs_param.vnfs_vtype      = type;
	vnfs_param.vnfs_str        = "bindfs";
	vnfs_param.vnfs_dvp        = dvp;
	vnfs_param.vnfs_fsnode     = (void *)xp;
	vnfs_param.vnfs_vops       = bindfs_vnodeop_p;
	vnfs_param.vnfs_markroot   = root;
	vnfs_param.vnfs_marksystem = 0;
	vnfs_param.vnfs_rdev       = 0;
	vnfs_param.vnfs_filesize   = 0; // set this to 0 since we should only be shadowing non-regular files
	vnfs_param.vnfs_cnp        = cnp;
	vnfs_param.vnfs_flags      = VNFS_ADDFSREF;

	error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vnfs_param, vpp);
	if (error == 0) {
		xp->bind_vnode = *vpp;
		xp->bind_myvid = vnode_vid(*vpp);
		vnode_settag(*vpp, VT_BINDFS);
	} else {
		FREE(xp, M_TEMP);
	}
	return error;
}

/*
 * Make a new or get existing bindfs node.
 * Vp is the alias vnode, lowervp is the lower vnode.
 *
 * lowervp is assumed to have an iocount on it from the caller
 */
int
bind_nodeget(
	struct mount * mp, struct vnode * lowervp, struct vnode * dvp, struct vnode ** vpp, struct componentname * cnp, int root)
{
	struct vnode * vp;
	int error;

	/* Lookup the hash firstly. */
	error = bind_hashget(mp, lowervp, vpp);
	/* ENOENT means it wasn't found, EIO is a failure we should bail from, 0 is it
	 * was found */
	if (error != ENOENT) {
		/* bind_hashget checked the vid, so if we got something here its legit to
		 * the best of our knowledge*/
		/* if we found something then there is an iocount on vpp,
		 *  if we didn't find something then vpp shouldn't be used by the caller */
		return error;
	}

	/*
	 * We do not serialize vnode creation, instead we will check for
	 * duplicates later, when adding new vnode to hash.
	 */
	error = vnode_ref(lowervp); // take a ref on lowervp so we let the system know we care about it
	if (error) {
		// Failed to get a reference on the lower vp so bail. Lowervp may be gone already.
		return error;
	}

	error = bind_getnewvnode(mp, lowervp, dvp, &vp, cnp, root);

	if (error) {
		vnode_rele(lowervp);
		return error;
	}

	/*
	 * Atomically insert our new node into the hash or vget existing
	 * if someone else has beaten us to it.
	 */
	error = bind_hashins(mp, VTOBIND(vp), vpp);
	if (error || *vpp != NULL) {
		/* recycle will call reclaim which will get rid of the internals */
		vnode_recycle(vp);
		vnode_put(vp);
		/* if we found vpp, then bind_hashins put an iocount on it */
		return error;
	}

	/* vp has an iocount from bind_getnewvnode */
	*vpp = vp;

	return 0;
}
