/*
 * Copyright (c) 1999-2005 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)hfs_lookup.c	1.0
 *	derived from @(#)ufs_lookup.c	8.15 (Berkeley) 6/16/95
 *
 *	(c) 1998-1999   Apple Computer, Inc.	 All Rights Reserved
 *	(c) 1990, 1992 	NeXT Computer, Inc.	All Rights Reserved
 *	
 *
 *	hfs_lookup.c -- code to handle directory traversal on HFS/HFS+ volume
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/paths.h>
#include <sys/kdebug.h>
#include <sys/kauth.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_cnode.h"

#define LEGACY_FORK_NAMES	1

static int forkcomponent(struct componentname *cnp, int *rsrcfork);

#define _PATH_DATAFORKSPEC	"/..namedfork/data"

#if LEGACY_FORK_NAMES
#define LEGACY_RSRCFORKSPEC	"/rsrc"
#endif

/*	
 * FROM FREEBSD 3.1
 * Convert a component of a pathname into a pointer to a locked cnode.
 * This is a very central and rather complicated routine.
 * If the file system is not maintained in a strict tree hierarchy,
 * this can result in a deadlock situation (see comments in code below).
 *
 * The cnp->cn_nameiop argument is LOOKUP, CREATE, RENAME, or DELETE depending
 * on whether the name is to be looked up, created, renamed, or deleted.
 * When CREATE, RENAME, or DELETE is specified, information usable in
 * creating, renaming, or deleting a directory entry may be calculated.
 * Notice that these are the only operations that can affect the directory of the target.
 *
 * LOCKPARENT and WANTPARENT actually refer to the parent of the last item,
 * so if ISLASTCN is not set, they should be ignored. Also they are mutually exclusive, or
 * WANTPARENT really implies DONTLOCKPARENT. Either of them set means that the calling
 * routine wants to access the parent of the target, locked or unlocked.
 *
 * Keeping the parent locked as long as possible protects from other processes
 * looking up the same item, so it has to be locked until the cnode is totally finished
 *
 * hfs_cache_lookup() performs the following for us:
 *	check that it is a directory
 *	check accessibility of directory
 *	check for modification attempts on read-only mounts
 *	if name found in cache
 *		if at end of path and deleting or creating
 *		drop it
 *		 else
 *		return name.
 *	return hfs_lookup()
 *
 * Overall outline of hfs_lookup:
 *
 *	handle simple cases of . and ..
 *	search for name in directory, to found or notfound
 * notfound:
 *	if creating, return locked directory, leaving info on available slots
 *	else return error
 * found:
 *	if at end of path and deleting, return information to allow delete
 *	if at end of path and rewriting (RENAME and LOCKPARENT), lock target
 *	  cnode and return info to allow rewrite
 *	if not at end, add name to cache; if at end and neither creating
 *	  nor deleting, add name to cache
 */


/*	
 *	Lookup *cnp in directory *dvp, return it in *vpp.
 *	**vpp is held on exit.
 *	We create a cnode for the file, but we do NOT open the file here.

#% lookup	dvp L ? ?
#% lookup	vpp - L -

	IN struct vnode *dvp - Parent node of file;
	INOUT struct vnode **vpp - node of target file, its a new node if
		the target vnode did not exist;
	IN struct componentname *cnp - Name of file;

 *	When should we lock parent_hp in here ??
 */
static int
hfs_lookup(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp, vfs_context_t context, int *cnode_locked)
{
	struct cnode *dcp;	/* cnode for directory being searched */
	struct vnode *tvp;	/* target vnode */
	struct hfsmount *hfsmp;
	kauth_cred_t cred;
	struct proc *p;
	int wantrsrc = 0;
	int forknamelen = 0;
	int flags;
	int nameiop;
	int retval = 0;
	int isDot;
	struct cat_desc desc;
	struct cat_desc cndesc;
	struct cat_attr attr;
	struct cat_fork fork;
	int lockflags;

	dcp = VTOC(dvp);
	hfsmp = VTOHFS(dvp);
	*vpp = NULL;
	*cnode_locked = 0;
	isDot = FALSE;
	tvp = NULL;
	nameiop = cnp->cn_nameiop;
	flags = cnp->cn_flags;
	bzero(&desc, sizeof(desc));

	cred = vfs_context_ucred(context);
	p    = vfs_context_proc(context);

	/*
	 * First check to see if it is a . or .., else look it up.
	 */
	if (flags & ISDOTDOT) {		/* Wanting the parent */
		cnp->cn_flags &= ~MAKEENTRY;
		goto found;	/* .. is always defined */
	} else if ((cnp->cn_nameptr[0] == '.') && (cnp->cn_namelen == 1)) {
		isDot = TRUE;
		cnp->cn_flags &= ~MAKEENTRY;
		goto found;	/* We always know who we are */
	} else {
		/* Check fork suffix to see if we want the resource fork */
		forknamelen = forkcomponent(cnp, &wantrsrc);
		
		/* Resource fork names are not cached. */
		if (wantrsrc)
			cnp->cn_flags &= ~MAKEENTRY;

		if (hfs_lock(dcp, HFS_EXCLUSIVE_LOCK) != 0) {
			goto notfound;
		}

		/* No need to go to catalog if there are no children */
		if (dcp->c_entries == 0) {
			hfs_unlock(dcp);
			goto notfound;
		}

		bzero(&cndesc, sizeof(cndesc));
		cndesc.cd_nameptr = cnp->cn_nameptr;
		cndesc.cd_namelen = cnp->cn_namelen;
		cndesc.cd_parentcnid = dcp->c_cnid;
		cndesc.cd_hint = dcp->c_childhint;

		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

		retval = cat_lookup(hfsmp, &cndesc, wantrsrc, &desc, &attr, &fork, NULL);
		
		hfs_systemfile_unlock(hfsmp, lockflags);

		if (retval == 0) {
			dcp->c_childhint = desc.cd_hint;
			hfs_unlock(dcp);
			goto found;
		}
		hfs_unlock(dcp);
notfound:
		/* ENAMETOOLONG supersedes other errors */
		if (((nameiop != CREATE) && (nameiop != RENAME)) && 
			(retval != ENAMETOOLONG) && 
		    (cnp->cn_namelen > kHFSPlusMaxFileNameChars)) {
			retval = ENAMETOOLONG;
		} else if (retval == 0) {
			retval = ENOENT;
		}
		/*
		 * This is a non-existing entry
		 *
		 * If creating, and at end of pathname and current
		 * directory has not been removed, then can consider
		 * allowing file to be created.
		 */
		if ((nameiop == CREATE || nameiop == RENAME ||
		    (nameiop == DELETE &&
		    (cnp->cn_flags & DOWHITEOUT) &&
		    (cnp->cn_flags & ISWHITEOUT))) &&
		    (flags & ISLASTCN) &&
		    (retval == ENOENT)) {
			retval = EJUSTRETURN;
			goto exit;
		}
		/*
		 * Insert name into cache (as non-existent) if appropriate.
		 *
		 * Only done for case-sensitive HFS+ volumes.
		 */
		if ((retval == ENOENT) &&
		    (hfsmp->hfs_flags & HFS_CASE_SENSITIVE) &&
		    (cnp->cn_flags & MAKEENTRY) && nameiop != CREATE) {
			cache_enter(dvp, NULL, cnp);
		}
		goto exit;
	}

found:
	/*
	 * Process any fork specifiers
	 */
	if (forknamelen && S_ISREG(attr.ca_mode)) {
		/* fork names are only for lookups */
		if ((nameiop != LOOKUP) && (nameiop != CREATE)) {
			retval = EPERM;  
			goto exit;
		}
		cnp->cn_consume = forknamelen;
		flags |= ISLASTCN;
	} else {
		wantrsrc = 0;
		forknamelen = 0;
	}
	if (flags & ISLASTCN) {
		switch(nameiop) {
		case DELETE:
			cnp->cn_flags &= ~MAKEENTRY;
			break;

		case RENAME:
			cnp->cn_flags &= ~MAKEENTRY;
			if (isDot) {
				retval = EISDIR;
				goto exit;
			}
			break;
		}
	}

	if (isDot) {
		if ((retval = vnode_get(dvp)))
			goto exit;
		*vpp = dvp;
	} else if (flags & ISDOTDOT) {
		if ((retval = hfs_vget(hfsmp, dcp->c_parentcnid, &tvp, 0)))
			goto exit;
		*cnode_locked = 1;
		*vpp = tvp;
	} else {
		int type = (attr.ca_mode & S_IFMT);

		if (!(flags & ISLASTCN) && (type != S_IFDIR) && (type != S_IFLNK)) {
			retval = ENOTDIR;
			goto exit;
		}

		/* Names with composed chars are not cached. */
		if (cnp->cn_namelen != desc.cd_namelen)
			cnp->cn_flags &= ~MAKEENTRY;

		/* Resource fork vnode names include the fork specifier. */
		if (wantrsrc && (flags & ISLASTCN))
			cnp->cn_namelen += forknamelen;

		retval = hfs_getnewvnode(hfsmp, dvp, cnp, &desc, wantrsrc, &attr, &fork, &tvp);

		if (wantrsrc && (flags & ISLASTCN))
			cnp->cn_namelen -= forknamelen;

		if (retval)
			goto exit;
		*cnode_locked = 1;
		*vpp = tvp;
	}
exit:
	cat_releasedesc(&desc);
	return (retval);
}



/*
 * Name caching works as follows:
 *
 * Names found by directory scans are retained in a cache
 * for future reference.  It is managed LRU, so frequently
 * used names will hang around.	 Cache is indexed by hash value
 * obtained from (vp, name) where vp refers to the directory
 * containing name.
 *
 * If it is a "negative" entry, (i.e. for a name that is known NOT to
 * exist) the vnode pointer will be NULL.
 *
 * Upon reaching the last segment of a path, if the reference
 * is for DELETE, or NOCACHE is set (rewrite), and the
 * name is located in the cache, it will be dropped.
 *
 */

#define	S_IXALL	0000111

__private_extern__
int
hfs_vnop_lookup(struct vnop_lookup_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp;
	struct cnode *cp;
	struct cnode *dcp;
	int error;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	int flags = cnp->cn_flags;
	int cnode_locked;

	*vpp = NULL;
	dcp = VTOC(dvp);

	/*
	 * Lookup an entry in the cache
	 *
	 * If the lookup succeeds, the vnode is returned in *vpp,
	 * and a status of -1 is returned.
	 *
	 * If the lookup determines that the name does not exist
	 * (negative cacheing), a status of ENOENT is returned.
	 *
	 * If the lookup fails, a status of zero is returned.
	 */
	error = cache_lookup(dvp, vpp, cnp);
	if (error != -1) {
		if (error == ENOENT)		/* found a negative cache entry */
			goto exit;
		goto lookup;			/* did not find it in the cache */
	}
	/*
	 * We have a name that matched
	 * cache_lookup returns the vp with an iocount reference already taken
	 */
	error = 0;
	vp = *vpp;

	/*
	 * If this is a hard-link vnode then we need to update
	 * the name (of the link), the parent ID, the cnid, the
	 * text encoding and the catalog hint.  This enables
	 * getattrlist calls to return the correct link info.
	 */
	cp = VTOC(vp);

	if ((flags & ISLASTCN) && (cp->c_flag & C_HARDLINK)) {
		hfs_lock(cp, HFS_FORCE_LOCK);
		if ((cp->c_parentcnid != VTOC(dvp)->c_cnid) ||
		    (bcmp(cnp->cn_nameptr, cp->c_desc.cd_nameptr, cp->c_desc.cd_namelen) != 0)) {
			struct cat_desc desc;
			int lockflags;

			/*
			 * Get an updated descriptor
			 */
			bzero(&desc, sizeof(desc));
			desc.cd_nameptr = cnp->cn_nameptr;
			desc.cd_namelen = cnp->cn_namelen;
			desc.cd_parentcnid = VTOC(dvp)->c_cnid;
			desc.cd_hint = VTOC(dvp)->c_childhint;
	
			lockflags = hfs_systemfile_lock(VTOHFS(dvp), SFL_CATALOG, HFS_SHARED_LOCK);		
			if (cat_lookup(VTOHFS(vp), &desc, 0, &desc, NULL, NULL, NULL) == 0)
				replace_desc(cp, &desc);
			hfs_systemfile_unlock(VTOHFS(dvp), lockflags);
		}
		hfs_unlock(cp);
	}
	if (dvp != vp && !(flags & ISDOTDOT)) {
		if ((flags & ISLASTCN) == 0 && vnode_isreg(vp)) {
			int wantrsrc = 0;

			cnp->cn_consume = forkcomponent(cnp, &wantrsrc);
			if (cnp->cn_consume) {
				flags |= ISLASTCN;
				/* Fork names are only for lookups */
				if (cnp->cn_nameiop != LOOKUP &&
				    cnp->cn_nameiop != CREATE) {
				        vnode_put(vp);
					error = EPERM;
					goto exit;
				}
			}
			/*
			 * Use cnode's rsrcfork vnode if possible.
			 */
			if (wantrsrc) {
			        int	vid;

			        *vpp = NULL;

			        if (cp->c_rsrc_vp == NULL) {
				        vnode_put(vp);
				        goto lookup;
				}
				vid = vnode_vid(cp->c_rsrc_vp);

				error = vnode_getwithvid(cp->c_rsrc_vp, vid);
				if (error) {
					vnode_put(vp);
				        goto lookup;
				}
				*vpp = cp->c_rsrc_vp;
				vnode_put(vp);
				vp = *vpp;
			}
		}
	}
	return (error);
	
lookup:
	/*
	 * The vnode was not in the name cache or it was stale.
	 *
	 * So we need to do a real lookup.
	 */
	cnode_locked = 0;

	error = hfs_lookup(dvp, vpp, cnp, ap->a_context, &cnode_locked);
	
	if (cnode_locked)
		hfs_unlock(VTOC(*vpp));
exit:
	return (error);
}


/*
 * forkcomponent - look for a fork suffix in the component name
 *
 */
static int
forkcomponent(struct componentname *cnp, int *rsrcfork)
{
	char *suffix = cnp->cn_nameptr + cnp->cn_namelen;
	int consume = 0;

	*rsrcfork = 0;
	if (*suffix == '\0')
		return (0);
	/*
	 * There are only 3 valid fork suffixes:
	 *	"/..namedfork/rsrc"
	 *	"/..namedfork/data"
	 *	"/rsrc"  (legacy)
	 */
	if (bcmp(suffix, _PATH_RSRCFORKSPEC, sizeof(_PATH_RSRCFORKSPEC)) == 0) {
		consume = sizeof(_PATH_RSRCFORKSPEC) - 1;
		*rsrcfork = 1;
	} else if (bcmp(suffix, _PATH_DATAFORKSPEC, sizeof(_PATH_DATAFORKSPEC)) == 0) {
		consume = sizeof(_PATH_DATAFORKSPEC) - 1;
	}

#if LEGACY_FORK_NAMES
	else if (bcmp(suffix, LEGACY_RSRCFORKSPEC, sizeof(LEGACY_RSRCFORKSPEC)) == 0) {
		consume = sizeof(LEGACY_RSRCFORKSPEC) - 1;
		*rsrcfork = 1;
		printf("HFS: /rsrc paths are deprecated (%s)\n", cnp->cn_nameptr);
	}
#endif
	return (consume);
}

