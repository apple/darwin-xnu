/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#include "nullfs.h"

/*
 * Null layer cache:
 * Each cache entry holds a reference to the lower vnode
 * along with a pointer to the alias vnode.  When an
 * entry is added the lower vnode is VREF'd.  When the
 * alias is removed the lower vnode is vrele'd.
 */

#define NULL_HASH_SIZE (desiredvnodes / 10)

/* osx doesn't really have the functionality freebsd uses here..gonna try this
 * hacked hash...*/
#define NULL_NHASH(vp) (&null_node_hashtbl[((((uintptr_t)vp) >> vnsz2log) + (uintptr_t)vnode_mount(vp)) & null_hash_mask])

static LIST_HEAD(null_node_hashhead, null_node) * null_node_hashtbl;
static lck_mtx_t null_hashmtx;
static lck_attr_t * null_hashlck_attr;
static lck_grp_t * null_hashlck_grp;
static lck_grp_attr_t * null_hashlck_grp_attr;
static u_long null_hash_mask;

/* os x doesn't have hashes built into vnode. gonna try doing what freebsd does
 *  anyway
 *  Don't want to create a dependency on vnode_internal.h and the real struct
 *  vnode.
 *  9 is an eyeball of the log 2 size of vnode */
static int vnsz2log = 9;

static int null_hashins(struct mount *, struct null_node *, struct vnode **);

int
nullfs_init_lck(lck_mtx_t * lck)
{
	int error = 1;
	if (lck && null_hashlck_grp && null_hashlck_attr) {
		lck_mtx_init(lck, null_hashlck_grp, null_hashlck_attr);
		error = 0;
	}
	return error;
}

int
nullfs_destroy_lck(lck_mtx_t * lck)
{
	int error = 1;
	if (lck && null_hashlck_grp) {
		lck_mtx_destroy(lck, null_hashlck_grp);
		error = 0;
	}
	return error;
}

/*
 * Initialise cache headers
 */
int
nullfs_init(__unused struct vfsconf * vfsp)
{
	NULLFSDEBUG("%s\n", __FUNCTION__);

	/* assuming for now that this happens immediately and by default after fs
	 * installation */
	null_hashlck_grp_attr = lck_grp_attr_alloc_init();
	if (null_hashlck_grp_attr == NULL) {
		goto error;
	}
	null_hashlck_grp = lck_grp_alloc_init("com.apple.filesystems.nullfs", null_hashlck_grp_attr);
	if (null_hashlck_grp == NULL) {
		goto error;
	}
	null_hashlck_attr = lck_attr_alloc_init();
	if (null_hashlck_attr == NULL) {
		goto error;
	}

	lck_mtx_init(&null_hashmtx, null_hashlck_grp, null_hashlck_attr);
	null_node_hashtbl = hashinit(NULL_HASH_SIZE, M_TEMP, &null_hash_mask);
	NULLFSDEBUG("%s finished\n", __FUNCTION__);
	return 0;
error:
	printf("NULLFS: failed to get lock element\n");
	if (null_hashlck_grp_attr) {
		lck_grp_attr_free(null_hashlck_grp_attr);
		null_hashlck_grp_attr = NULL;
	}
	if (null_hashlck_grp) {
		lck_grp_free(null_hashlck_grp);
		null_hashlck_grp = NULL;
	}
	if (null_hashlck_attr) {
		lck_attr_free(null_hashlck_attr);
		null_hashlck_attr = NULL;
	}
	return KERN_FAILURE;
}

int
nullfs_uninit()
{
	/* This gets called when the fs is uninstalled, there wasn't an exact
	 * equivalent in vfsops */
	lck_mtx_destroy(&null_hashmtx, null_hashlck_grp);
	FREE(null_node_hashtbl, M_TEMP);
	if (null_hashlck_grp_attr) {
		lck_grp_attr_free(null_hashlck_grp_attr);
		null_hashlck_grp_attr = NULL;
	}
	if (null_hashlck_grp) {
		lck_grp_free(null_hashlck_grp);
		null_hashlck_grp = NULL;
	}
	if (null_hashlck_attr) {
		lck_attr_free(null_hashlck_attr);
		null_hashlck_attr = NULL;
	}
	return 0;
}

/*
 * Find the nullfs vnode mapped to lowervp. Return it in *vpp with an iocount if found.
 * Return 0 on success. On failure *vpp will be null and a non-zero error code will be returned.
 */
int
null_hashget(struct mount * mp, struct vnode * lowervp, struct vnode ** vpp)
{
	struct null_node_hashhead * hd;
	struct null_node * a;
	struct vnode * vp;
	int error = ENOENT;

	/*
	 * Find hash base, and then search the (two-way) linked
	 * list looking for a null_node structure which is referencing
	 * the lower vnode. We only give up our reference at reclaim so
	 * just check whether the lowervp has gotten pulled from under us
	 */
	hd = NULL_NHASH(lowervp);
	lck_mtx_lock(&null_hashmtx);
	LIST_FOREACH(a, hd, null_hash)
	{
		if (a->null_lowervp == lowervp && vnode_mount(NULLTOV(a)) == mp) {
			vp = NULLTOV(a);
			if (a->null_lowervid != vnode_vid(lowervp)) {
				/*lowervp has reved */
				error = EIO;
			} else {
				/* if we found something then get an iocount on it */
				error = vnode_getwithvid(vp, a->null_myvid);
				if (error == 0) {
					*vpp = vp;
				}
			}
			break;
		}
	}
	lck_mtx_unlock(&null_hashmtx);
	return error;
}

/*
 * Act like null_hashget, but add passed null_node to hash if no existing
 * node found.
 */
static int
null_hashins(struct mount * mp, struct null_node * xp, struct vnode ** vpp)
{
	struct null_node_hashhead * hd;
	struct null_node * oxp;
	struct vnode * ovp;
	int error = 0;

	hd = NULL_NHASH(xp->null_lowervp);
	lck_mtx_lock(&null_hashmtx);
	LIST_FOREACH(oxp, hd, null_hash)
	{
		if (oxp->null_lowervp == xp->null_lowervp && vnode_mount(NULLTOV(oxp)) == mp) {
			/*
			 * See null_hashget for a description of this
			 * operation.
			 */
			ovp = NULLTOV(oxp);
			if (oxp->null_lowervid != vnode_vid(oxp->null_lowervp)) {
				/*vp doesn't exist so return null (not sure we are actually gonna catch
				 *  recycle right now
				 *  This is an exceptional case right now, it suggests the vnode we are
				 *  trying to add has been recycled
				 *  don't add it.*/
				error = EIO;
				goto end;
			}
			/* if we found something in the hash map then grab an iocount */
			error = vnode_getwithvid(ovp, oxp->null_myvid);
			if (error == 0) {
				*vpp = ovp;
			}
			goto end;
		}
	}
	/* if it wasn't in the hash map then the vnode pointed to by xp already has a
	 * iocount so don't bother */
	LIST_INSERT_HEAD(hd, xp, null_hash);
	xp->null_flags |= NULL_FLAG_HASHED;
end:
	lck_mtx_unlock(&null_hashmtx);
	return error;
}

/*
 * Remove node from hash.
 */
void
null_hashrem(struct null_node * xp)
{
	lck_mtx_lock(&null_hashmtx);
	LIST_REMOVE(xp, null_hash);
	lck_mtx_unlock(&null_hashmtx);
}

static struct null_node *
null_nodecreate(struct vnode * lowervp)
{
	struct null_node * xp;

	MALLOC(xp, struct null_node *, sizeof(struct null_node), M_TEMP, M_WAITOK | M_ZERO);
	if (xp != NULL) {
		if (lowervp) {
			xp->null_lowervp  = lowervp;
			xp->null_lowervid = vnode_vid(lowervp);
		}
	}
	return xp;
}

/* assumption is that vnode has iocount on it after vnode create */
int
null_getnewvnode(
	struct mount * mp, struct vnode * lowervp, struct vnode * dvp, struct vnode ** vpp, struct componentname * cnp, int root)
{
	struct vnode_fsparam vnfs_param;
	int error             = 0;
	enum vtype type       = VDIR;
	struct null_node * xp = null_nodecreate(lowervp);

	if (xp == NULL) {
		return ENOMEM;
	}

	if (lowervp) {
		type = vnode_vtype(lowervp);
	}

	vnfs_param.vnfs_mp         = mp;
	vnfs_param.vnfs_vtype      = type;
	vnfs_param.vnfs_str        = "nullfs";
	vnfs_param.vnfs_dvp        = dvp;
	vnfs_param.vnfs_fsnode     = (void *)xp;
	vnfs_param.vnfs_vops       = nullfs_vnodeop_p;
	vnfs_param.vnfs_markroot   = root;
	vnfs_param.vnfs_marksystem = 0;
	vnfs_param.vnfs_rdev       = 0;
	vnfs_param.vnfs_filesize   = 0; // set this to 0 since we should only be shadowing non-regular files
	vnfs_param.vnfs_cnp        = cnp;
	vnfs_param.vnfs_flags      = VNFS_ADDFSREF;

	error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vnfs_param, vpp);
	if (error == 0) {
		xp->null_vnode = *vpp;
		xp->null_myvid = vnode_vid(*vpp);
		vnode_settag(*vpp, VT_NULL);
	} else {
		FREE(xp, M_TEMP);
	}
	return error;
}

/*
 * Make a new or get existing nullfs node.
 * Vp is the alias vnode, lowervp is the lower vnode.
 *
 * lowervp is assumed to have an iocount on it from the caller
 */
int
null_nodeget(
	struct mount * mp, struct vnode * lowervp, struct vnode * dvp, struct vnode ** vpp, struct componentname * cnp, int root)
{
	struct vnode * vp;
	int error;

	/* Lookup the hash firstly. */
	error = null_hashget(mp, lowervp, vpp);
	/* ENOENT means it wasn't found, EIO is a failure we should bail from, 0 is it
	 * was found */
	if (error != ENOENT) {
		/* null_hashget checked the vid, so if we got something here its legit to
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

	error = null_getnewvnode(mp, lowervp, dvp, &vp, cnp, root);

	if (error) {
		vnode_rele(lowervp);
		return error;
	}

	/*
	 * Atomically insert our new node into the hash or vget existing
	 * if someone else has beaten us to it.
	 */
	error = null_hashins(mp, VTONULL(vp), vpp);
	if (error || *vpp != NULL) {
		/* recycle will call reclaim which will get rid of the internals */
		vnode_recycle(vp);
		vnode_put(vp);
		/* if we found vpp, then null_hashins put an iocount on it */
		return error;
	}

	/* vp has an iocount from null_getnewvnode */
	*vpp = vp;

	return 0;
}
