/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Poul-Henning Kamp of the FreeBSD Project.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 *
 *	@(#)vfs_cache.c	8.5 (Berkeley) 3/22/95
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/errno.h>
#include <sys/malloc.h>

/*
 * Name caching works as follows:
 *
 * Names found by directory scans are retained in a cache
 * for future reference.  It is managed LRU, so frequently
 * used names will hang around.  Cache is indexed by hash value
 * obtained from (vp, name) where vp refers to the directory
 * containing name.
 *
 * If it is a "negative" entry, (i.e. for a name that is known NOT to
 * exist) the vnode pointer will be NULL.
 *
 * For simplicity (and economy of storage), names longer than
 * a maximum length of NCHNAMLEN are not cached; they occur
 * infrequently in any case, and are almost never of interest.
 *
 * Upon reaching the last segment of a path, if the reference
 * is for DELETE, or NOCACHE is set (rewrite), and the
 * name is located in the cache, it will be dropped.
 */

/*
 * Structures associated with name cacheing.
 */
#define NCHHASH(dvp, cnp) \
	(&nchashtbl[((dvp)->v_id + (cnp)->cn_hash) & nchash])
LIST_HEAD(nchashhead, namecache) *nchashtbl;	/* Hash Table */
u_long	nchash;				/* size of hash table - 1 */
long	numcache;			/* number of cache entries allocated */
TAILQ_HEAD(, namecache) nclruhead;	/* LRU chain */
struct	nchstats nchstats;		/* cache effectiveness statistics */
u_long nextvnodeid = 0;
int doingcache = 1;			/* 1 => enable the cache */

/*
 * Delete an entry from its hash list and move it to the front
 * of the LRU list for immediate reuse.
 */
#if DIAGNOSTIC
#define PURGE(ncp)  {						\
	if (ncp->nc_hash.le_prev == 0)				\
		panic("namecache purge le_prev");		\
	if (ncp->nc_hash.le_next == ncp)			\
		panic("namecache purge le_next");		\
	LIST_REMOVE(ncp, nc_hash);				\
	ncp->nc_hash.le_prev = 0;				\
	TAILQ_REMOVE(&nclruhead, ncp, nc_lru);			\
	TAILQ_INSERT_HEAD(&nclruhead, ncp, nc_lru);		\
}
#else
#define PURGE(ncp)  {						\
	LIST_REMOVE(ncp, nc_hash);				\
	ncp->nc_hash.le_prev = 0;				\
	TAILQ_REMOVE(&nclruhead, ncp, nc_lru);			\
	TAILQ_INSERT_HEAD(&nclruhead, ncp, nc_lru);		\
}
#endif /* DIAGNOSTIC */

/*
 * Move an entry that has been used to the tail of the LRU list
 * so that it will be preserved for future use.
 */
#define TOUCH(ncp)  {						\
	if (ncp->nc_lru.tqe_next != 0) {			\
		TAILQ_REMOVE(&nclruhead, ncp, nc_lru);		\
		TAILQ_INSERT_TAIL(&nclruhead, ncp, nc_lru);	\
	}							\
}

/*
 * Lookup an entry in the cache 
 *
 * We don't do this if the segment name is long, simply so the cache 
 * can avoid holding long names (which would either waste space, or
 * add greatly to the complexity).
 *
 * Lookup is called with dvp pointing to the directory to search,
 * cnp pointing to the name of the entry being sought. If the lookup
 * succeeds, the vnode is returned in *vpp, and a status of -1 is
 * returned. If the lookup determines that the name does not exist
 * (negative cacheing), a status of ENOENT is returned. If the lookup
 * fails, a status of zero is returned.
 */

int
cache_lookup(dvp, vpp, cnp)
	struct vnode *dvp;
	struct vnode **vpp;
	struct componentname *cnp;
{
	register struct namecache *ncp, *nnp;
	register struct nchashhead *ncpp;

	if (!doingcache) {
		cnp->cn_flags &= ~MAKEENTRY;
		return (0);
	}
	if (cnp->cn_namelen > NCHNAMLEN) {
		nchstats.ncs_long++;
		cnp->cn_flags &= ~MAKEENTRY;
		return (0);
	}

	ncpp = NCHHASH(dvp, cnp);
	for (ncp = ncpp->lh_first; ncp != 0; ncp = nnp) {
		nnp = ncp->nc_hash.le_next;
		/* If one of the vp's went stale, don't bother anymore. */
		if ((ncp->nc_dvpid != ncp->nc_dvp->v_id) ||
		    (ncp->nc_vp && ncp->nc_vpid != ncp->nc_vp->v_id)) {
			nchstats.ncs_falsehits++;
			PURGE(ncp);
			continue;
		}
		/* Now that we know the vp's to be valid, is it ours ? */
		if (ncp->nc_dvp == dvp &&
		    ncp->nc_nlen == cnp->cn_namelen &&
		    !bcmp(ncp->nc_name, cnp->cn_nameptr, (u_int)ncp->nc_nlen))
			break;
	}

	/* We failed to find an entry */
	if (ncp == 0) {
		nchstats.ncs_miss++;
		return (0);
	}

	/* We don't want to have an entry, so dump it */
	if ((cnp->cn_flags & MAKEENTRY) == 0) {
		nchstats.ncs_badhits++;
		PURGE(ncp);
		return (0);
	} 

	/* We found a "positive" match, return the vnode */
        if (ncp->nc_vp) {
		nchstats.ncs_goodhits++;
		TOUCH(ncp);
		*vpp = ncp->nc_vp;
		return (-1);
	}

	/* We found a negative match, and want to create it, so purge */
	if (cnp->cn_nameiop == CREATE) {
		nchstats.ncs_badhits++;
		PURGE(ncp);
		return (0);
	}

	/*
	 * We found a "negative" match, ENOENT notifies client of this match.
	 * The nc_vpid field records whether this is a whiteout.
	 */
	nchstats.ncs_neghits++;
	TOUCH(ncp);
	cnp->cn_flags |= ncp->nc_vpid;
	return (ENOENT);
}

/*
 * Add an entry to the cache.
 */
void
cache_enter(dvp, vp, cnp)
	struct vnode *dvp;
	struct vnode *vp;
	struct componentname *cnp;
{
	register struct namecache *ncp;
	register struct nchashhead *ncpp;

	if (!doingcache)
		return;

	/*
	 * If an entry that is too long, is entered, bad things happen.
	 * cache_lookup acts as the sentinel to make sure longer names
	 * are not stored. This here will prevent outsiders from doing
	 * something that is unexpected.
	 */
	if (cnp->cn_namelen > NCHNAMLEN)
		panic("cache_enter: name too long");

	/*
	 * We allocate a new entry if we are less than the maximum
	 * allowed and the one at the front of the LRU list is in use.
	 * Otherwise we use the one at the front of the LRU list.
	 */
	if (numcache < desiredvnodes &&
	    ((ncp = nclruhead.tqh_first) == NULL ||
	    ncp->nc_hash.le_prev != 0)) {
		/* Add one more entry */
		ncp = (struct namecache *)
			_MALLOC_ZONE((u_long)sizeof *ncp, M_CACHE, M_WAITOK);
		numcache++;
	} else if (ncp = nclruhead.tqh_first) {
		/* reuse an old entry */
		TAILQ_REMOVE(&nclruhead, ncp, nc_lru);
		if (ncp->nc_hash.le_prev != 0) {
#if DIAGNOSTIC
			if (ncp->nc_hash.le_next == ncp)
				panic("cache_enter: le_next");
#endif
			LIST_REMOVE(ncp, nc_hash);
			ncp->nc_hash.le_prev = 0;
		}
	} else {
		/* give up */
		return;
	}

	/*
	 * Fill in cache info, if vp is NULL this is a "negative" cache entry.
	 * For negative entries, we have to record whether it is a whiteout.
	 * the whiteout flag is stored in the nc_vpid field which is
	 * otherwise unused.
	 */
	ncp->nc_vp = vp;
	if (vp)
		ncp->nc_vpid = vp->v_id;
	else
		ncp->nc_vpid = cnp->cn_flags & ISWHITEOUT;
	ncp->nc_dvp = dvp;
	ncp->nc_dvpid = dvp->v_id;
	ncp->nc_nlen = cnp->cn_namelen;
	bcopy(cnp->cn_nameptr, ncp->nc_name, (unsigned)ncp->nc_nlen);
	TAILQ_INSERT_TAIL(&nclruhead, ncp, nc_lru);
	ncpp = NCHHASH(dvp, cnp);
#if DIAGNOSTIC
	{
		register struct namecache *p;

		for (p = ncpp->lh_first; p != 0; p = p->nc_hash.le_next)
			if (p == ncp)
				panic("cache_enter: duplicate");
	}
#endif
	LIST_INSERT_HEAD(ncpp, ncp, nc_hash);
}

/*
 * Name cache initialization, from vfs_init() when we are booting
 */
void
nchinit()
{

	TAILQ_INIT(&nclruhead);
	nchashtbl = hashinit(desiredvnodes, M_CACHE, &nchash);
}

/*
 * Invalidate a all entries to particular vnode.
 * 
 * We actually just increment the v_id, that will do it. The entries will
 * be purged by lookup as they get found. If the v_id wraps around, we
 * need to ditch the entire cache, to avoid confusion. No valid vnode will
 * ever have (v_id == 0).
 */
void
cache_purge(vp)
	struct vnode *vp;
{
	struct namecache *ncp;
	struct nchashhead *ncpp;

	vp->v_id = ++nextvnodeid;
	if (nextvnodeid != 0)
		return;
	for (ncpp = &nchashtbl[nchash]; ncpp >= nchashtbl; ncpp--) {
		while (ncp = ncpp->lh_first)
			PURGE(ncp);
	}
	vp->v_id = ++nextvnodeid;
}

/*
 * Flush all entries referencing a particular filesystem.
 *
 * Since we need to check it anyway, we will flush all the invalid
 * entriess at the same time.
 */
void
cache_purgevfs(mp)
	struct mount *mp;
{
	struct nchashhead *ncpp;
	struct namecache *ncp, *nnp;

	/* Scan hash tables for applicable entries */
	for (ncpp = &nchashtbl[nchash]; ncpp >= nchashtbl; ncpp--) {
		for (ncp = ncpp->lh_first; ncp != 0; ncp = nnp) {
			nnp = ncp->nc_hash.le_next;
			if (ncp->nc_dvpid != ncp->nc_dvp->v_id ||
			    (ncp->nc_vp && ncp->nc_vpid != ncp->nc_vp->v_id) ||
			    ncp->nc_dvp->v_mount == mp) {
				PURGE(ncp);
			}
		}
	}
}
