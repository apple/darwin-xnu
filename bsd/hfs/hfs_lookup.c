/*
 * Copyright (c) 1999-2015 Apple Inc. All rights reserved.
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
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/kdebug.h>
#include <sys/kauth.h>
#include <sys/namei.h>
#include <sys/user.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_cnode.h"


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
hfs_lookup(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp, int *cnode_locked, int force_casesensitive_lookup)
{
	struct cnode *dcp;	/* cnode for directory being searched */
	struct vnode *tvp;	/* target vnode */
	struct hfsmount *hfsmp;
	int flags;
	int nameiop;
	int retval = 0;
	int isDot;
	struct cat_desc desc;
	struct cat_desc cndesc;
	struct cat_attr attr;
	struct cat_fork fork;
	int lockflags;
	int newvnode_flags;

  retry:
	newvnode_flags = 0;
	dcp = NULL;
	hfsmp = VTOHFS(dvp);
	*vpp = NULL;
	*cnode_locked = 0;
	isDot = FALSE;
	tvp = NULL;
	nameiop = cnp->cn_nameiop;
	flags = cnp->cn_flags;
	bzero(&desc, sizeof(desc));

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
		if (hfs_lock(VTOC(dvp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) != 0) {
			retval = ENOENT;  /* The parent no longer exists ? */
			goto exit;
		}
		dcp = VTOC(dvp);

		if (dcp->c_flag & C_DIR_MODIFICATION) {
		    // XXXdbg - if we could msleep on a lck_rw_t then we would do that
		    //          but since we can't we have to unlock, delay for a bit
		    //          and then retry...
		    // msleep((caddr_t)&dcp->c_flag, &dcp->c_rwlock, PINOD, "hfs_vnop_lookup", 0);
		    hfs_unlock(dcp);
		    tsleep((caddr_t)dvp, PRIBIO, "hfs_lookup", 1);

		    goto retry;
		}


		/*
		 * We shouldn't need to go to the catalog if there are no children.
		 * However, in the face of a minor disk corruption where the valence of
		 * the directory is off, we could infinite loop here if we return ENOENT
		 * even though there are actually items in the directory.  (create will
		 * see the ENOENT, try to create something, which will return with 
		 * EEXIST over and over again).  As a result, always check the catalog.
		 */

		bzero(&cndesc, sizeof(cndesc));
		cndesc.cd_nameptr = (const u_int8_t *)cnp->cn_nameptr;
		cndesc.cd_namelen = cnp->cn_namelen;
		cndesc.cd_parentcnid = dcp->c_fileid;
		cndesc.cd_hint = dcp->c_childhint;

		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

		retval = cat_lookup(hfsmp, &cndesc, 0, force_casesensitive_lookup, &desc, &attr, &fork, NULL);
		
		hfs_systemfile_unlock(hfsmp, lockflags);

		if (retval == 0) {
			dcp->c_childhint = desc.cd_hint;
			/*
			 * Note: We must drop the parent lock here before calling
			 * hfs_getnewvnode (which takes the child lock).
			 */
			hfs_unlock(dcp);
			dcp = NULL;
			
			/* Verify that the item just looked up isn't one of the hidden directories. */
			if (desc.cd_cnid == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid ||
				desc.cd_cnid == hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) {
				retval = ENOENT;
				goto exit;
			}
			
			goto found;
		}
		
		/*
		 * ENAMETOOLONG supersedes other errors
		 *
		 * For a CREATE or RENAME operation on the last component
		 * the ENAMETOOLONG will be handled in the next VNOP.
		 */
		if ((retval != ENAMETOOLONG) && 
		    (cnp->cn_namelen > kHFSPlusMaxFileNameChars) &&
		    (((flags & ISLASTCN) == 0) || ((nameiop != CREATE) && (nameiop != RENAME)))) {
			retval = ENAMETOOLONG;
		} else if (retval == 0) {
			retval = ENOENT;
		} else if (retval == ERESERVEDNAME) {
			/*
			 * We found the name in the catalog, but it is unavailable
			 * to us. The exact error to return to our caller depends
			 * on the operation, and whether we've already reached the
			 * last path component. In all cases, avoid a negative
			 * cache entry, since someone else may be able to access
			 * the name if their lookup is configured differently.
			 */

			cnp->cn_flags &= ~MAKEENTRY;

			if (((flags & ISLASTCN) == 0) || ((nameiop == LOOKUP) || (nameiop == DELETE))) {
				/* A reserved name for a pure lookup is the same as the path not being present */
				retval = ENOENT;
			} else {
				/* A reserved name with intent to create must be rejected as impossible */
				retval = EEXIST;
			}
		}
		if (retval != ENOENT)
			goto exit;
		/*
		 * This is a non-existing entry
		 *
		 * If creating, and at end of pathname and current
		 * directory has not been removed, then can consider
		 * allowing file to be created.
		 */
		if ((nameiop == CREATE || nameiop == RENAME) &&
		    (flags & ISLASTCN) &&
		    !(ISSET(dcp->c_flag, C_DELETED | C_NOEXISTS))) {
			retval = EJUSTRETURN;
			goto exit;
		}
		/*
		 * Insert name into the name cache (as non-existent).
		 */
		if ((hfsmp->hfs_flags & HFS_STANDARD) == 0 &&
		    (cnp->cn_flags & MAKEENTRY) &&
		    (nameiop != CREATE)) {
			cache_enter(dvp, NULL, cnp);
			dcp->c_flag |= C_NEG_ENTRIES;
		}
		goto exit;
	}

found:
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
		/*
		 * Directory hard links can have multiple parents so
		 * find the appropriate parent for the current thread.
		 */
		if ((retval = hfs_vget(hfsmp, hfs_currentparent(VTOC(dvp),
									/* have_lock: */ false), &tvp, 0, 0))) {
			goto exit;
		}
		*cnode_locked = 1;
		*vpp = tvp;
	} else {
		int type = (attr.ca_mode & S_IFMT);

		if (!(flags & ISLASTCN) && (type != S_IFDIR) && (type != S_IFLNK)) {
			retval = ENOTDIR;
			goto exit;
		}
		/* Don't cache directory hardlink names. */
		if (attr.ca_recflags & kHFSHasLinkChainMask) {
			cnp->cn_flags &= ~MAKEENTRY;
		}
		/* Names with composed chars are not cached. */
		if (cnp->cn_namelen != desc.cd_namelen)
			cnp->cn_flags &= ~MAKEENTRY;

		retval = hfs_getnewvnode(hfsmp, dvp, cnp, &desc, 0, &attr, &fork, &tvp, &newvnode_flags);

		if (retval) {
			/*
			 * If this was a create/rename operation lookup, then by this point
			 * we expected to see the item returned from hfs_getnewvnode above.  
			 * In the create case, it would probably eventually bubble out an EEXIST 
			 * because the item existed when we were trying to create it.  In the 
			 * rename case, it would let us know that we need to go ahead and 
			 * delete it as part of the rename.  However, if we hit the condition below
			 * then it means that we found the element during cat_lookup above, but 
			 * it is now no longer there.  We simply behave as though we never found
			 * the element at all and return EJUSTRETURN.
			 */  
			if ((retval == ENOENT) &&
					((cnp->cn_nameiop == CREATE) || (cnp->cn_nameiop == RENAME)) &&
					(flags & ISLASTCN)) {
				retval = EJUSTRETURN;
			}
			
			/*
			 * If this was a straight lookup operation, we may need to redrive the entire 
			 * lookup starting from cat_lookup if the element was deleted as the result of 
			 * a rename operation.  Since rename is supposed to guarantee atomicity, then
			 * lookups cannot fail because the underlying element is deleted as a result of
			 * the rename call -- either they returned the looked up element prior to rename
			 * or return the newer element.  If we are in this region, then all we can do is add
			 * workarounds to guarantee the latter case. The element has already been deleted, so
			 * we just re-try the lookup to ensure the caller gets the most recent element.
			 */
			if ((retval == ENOENT) && (cnp->cn_nameiop == LOOKUP) &&
				(newvnode_flags & (GNV_CHASH_RENAMED | GNV_CAT_DELETED))) {
				if (dcp) {
					hfs_unlock (dcp);
				}
				/* get rid of any name buffers that may have lingered from the cat_lookup call */
				cat_releasedesc (&desc);
				goto retry;
			}

			/* Also, re-drive the lookup if the item we looked up was a hardlink, and the number 
			 * or name of hardlinks has changed in the interim between the cat_lookup above, and
			 * our call to hfs_getnewvnode.  hfs_getnewvnode will validate the cattr we passed it
			 * against what is actually in the catalog after the cnode is created.  If there were
			 * any issues, it will bubble out ERECYCLE, which we need to swallow and use as the
			 * key to redrive as well.  We need to special case this below because in this case, 
			 * it needs to occur regardless of the type of lookup we're doing here.  
			 */
			if ((retval == ERECYCLE) && (newvnode_flags & GNV_CAT_ATTRCHANGED)) {
				if (dcp) {
					hfs_unlock (dcp);
				}
				/* get rid of any name buffers that may have lingered from the cat_lookup call */
				cat_releasedesc (&desc);
				retval = 0;
				goto retry;
			}

			/* skip to the error-handling code if we can't retry */
			goto exit;
		}

		/* 
		 * Save the origin info for file and directory hardlinks.  Directory hardlinks 
		 * need the origin for '..' lookups, and file hardlinks need it to ensure that 
		 * competing lookups do not cause us to vend different hardlinks than the ones requested.
		 */
		if (ISSET(VTOC(tvp)->c_flag, C_HARDLINK))
			hfs_savelinkorigin(VTOC(tvp), VTOC(dvp)->c_fileid);
		*cnode_locked = 1;
		*vpp = tvp;
	}
exit:
	if (dcp) {
		hfs_unlock(dcp);
	}
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

int
hfs_vnop_lookup(struct vnop_lookup_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp;
	struct cnode *cp;
	struct cnode *dcp;
	struct hfsmount *hfsmp;
	int error;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct proc *p = vfs_context_proc(ap->a_context);
	int flags = cnp->cn_flags;
	int force_casesensitive_lookup = proc_is_forcing_hfs_case_sensitivity(p);
	int cnode_locked;
	int fastdev_candidate = 0;
	int auto_candidate = 0;

	*vpp = NULL;
	dcp = VTOC(dvp);
	hfsmp = VTOHFS(dvp);

	if ((hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) && (vnode_isfastdevicecandidate(dvp) || (dcp->c_attr.ca_recflags & kHFSFastDevCandidateMask)) ){
		fastdev_candidate = 1;
		auto_candidate = (vnode_isautocandidate(dvp) || (dcp->c_attr.ca_recflags & kHFSAutoCandidateMask));
	}
	

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
		if ((error == ENOENT) && (cnp->cn_nameiop != CREATE))		
			goto exit;	/* found a negative cache entry */
		goto lookup;		/* did not find it in the cache */
	}
	/*
	 * We have a name that matched
	 * cache_lookup returns the vp with an iocount reference already taken
	 */
	error = 0;
	vp = *vpp;
	cp = VTOC(vp);
	
	/* We aren't allowed to vend out vp's via lookup to the hidden directory */
	if (cp->c_cnid == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid ||
		cp->c_cnid == hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) {
		/* Drop the iocount from cache_lookup */
		vnode_put (vp);
		error = ENOENT;
		goto exit;
	}
	
	if (cp->c_attr.ca_recflags & kHFSDoNotFastDevPinMask) {
		fastdev_candidate = 0;
	}

	/*
	 * If this is a hard-link vnode then we need to update
	 * the name (of the link), the parent ID, the cnid, the
	 * text encoding and the catalog hint.  This enables
	 * getattrlist calls to return the correct link info.
	 */

	/*
	 * Alternatively, if we are forcing a case-sensitive lookup
	 * on a case-insensitive volume, the namecache entry
	 * may have been for an incorrect case. Since we cannot
	 * determine case vs. normalization, redrive the catalog
	 * lookup based on any byte mismatch.
	 */
	if (((flags & ISLASTCN) && (cp->c_flag & C_HARDLINK))
		|| (force_casesensitive_lookup && !(hfsmp->hfs_flags & HFS_CASE_SENSITIVE))) {
		int stale_link = 0;

		hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);	
		if ((cp->c_parentcnid != dcp->c_cnid) ||
		    (cnp->cn_namelen != cp->c_desc.cd_namelen) ||
		    (bcmp(cnp->cn_nameptr, cp->c_desc.cd_nameptr, cp->c_desc.cd_namelen) != 0)) {
			struct cat_desc desc;
			struct cat_attr lookup_attr;
			int lockflags;

			if (force_casesensitive_lookup && !(hfsmp->hfs_flags & HFS_CASE_SENSITIVE)) {
				/*
				 * Since the name in the cnode doesn't match our lookup
				 * string exactly, do a full lookup.
				 */
				hfs_unlock (cp);

				vnode_put(vp);
				goto lookup;
			}

			/*
			 * Get an updated descriptor
			 */
			desc.cd_nameptr = (const u_int8_t *)cnp->cn_nameptr;
			desc.cd_namelen = cnp->cn_namelen;
			desc.cd_parentcnid = dcp->c_fileid;
			desc.cd_hint = dcp->c_childhint;
			desc.cd_encoding = 0;
			desc.cd_cnid = 0;
			desc.cd_flags = S_ISDIR(cp->c_mode) ? CD_ISDIR : 0;

			/*
			 * Because lookups call replace_desc to put a new descriptor in
			 * the cnode we are modifying it is possible that this cnode's 
			 * descriptor is out of date for the parent ID / name that
			 * we are trying to look up. (It may point to a different hardlink).
			 *
			 * We need to be cautious that when re-supplying the 
			 * descriptor below that the results of the catalog lookup
			 * still point to the same raw inode for the hardlink.  This would 
			 * not be the case if we found something in the cache above but 
			 * the vnode it returned no longer has a valid hardlink for the 
			 * parent ID/filename combo we are requesting.  (This is because 
			 * hfs_unlink does not directly trigger namecache removal). 
			 *
			 * As a result, before vending out the vnode (and replacing
			 * its descriptor) verify that the fileID is the same by comparing
			 * the in-cnode attributes vs. the one returned from the lookup call
			 * below.  If they do not match, treat this lookup as if we never hit
			 * in the cache at all.
			 */

			lockflags = hfs_systemfile_lock(VTOHFS(dvp), SFL_CATALOG, HFS_SHARED_LOCK);		
		
			error = cat_lookup(VTOHFS(vp), &desc, 0, 0, &desc, &lookup_attr, NULL, NULL);	
			
			hfs_systemfile_unlock(VTOHFS(dvp), lockflags);

			/* 
			 * Note that cat_lookup may fail to find something with the name provided in the
			 * stack-based descriptor above. In that case, an ENOENT is a legitimate errno
			 * to be placed in error, which will get returned in the fastpath below.
			 */
			if (error == 0) {
				if (lookup_attr.ca_fileid == cp->c_attr.ca_fileid) {
					/* It still points to the right raw inode.  Replacing the descriptor is fine */
					replace_desc (cp, &desc);

					/* 
					 * Save the origin info for file and directory hardlinks.  Directory hardlinks 
					 * need the origin for '..' lookups, and file hardlinks need it to ensure that 
					 * competing lookups do not cause us to vend different hardlinks than the ones requested.
					 */
					hfs_savelinkorigin(cp, dcp->c_fileid);
				}
				else {
					/* If the fileID does not match then do NOT replace the descriptor! */
					stale_link = 1;
				}	
			}
		}
		hfs_unlock (cp);
		
		if (stale_link) {
			/* 
			 * If we had a stale_link, then we need to pretend as though
			 * we never found this vnode and force a lookup through the 
			 * traditional path.  Drop the iocount acquired through 
			 * cache_lookup above and force a cat lookup / getnewvnode
			 */
			vnode_put(vp);
			goto lookup;
		}
		
		if (error) {
			/* 
			 * If the cat_lookup failed then the caller will not expect 
			 * a vnode with an iocount on it.
			 */
			vnode_put(vp);
		}

	}	
	goto exit;
	
lookup:
	/*
	 * The vnode was not in the name cache or it was stale.
	 *
	 * So we need to do a real lookup.
	 */
	cnode_locked = 0;

	error = hfs_lookup(dvp, vpp, cnp, &cnode_locked, force_casesensitive_lookup);
	
	if (*vpp && (VTOC(*vpp)->c_attr.ca_recflags & kHFSDoNotFastDevPinMask)) {
		fastdev_candidate = 0;
	}

	if (*vpp && (VTOC(*vpp)->c_attr.ca_recflags & kHFSAutoCandidateMask)) {
		//printf("vp %s / %d is an auto-candidate\n", (*vpp)->v_name ? (*vpp)->v_name : "no-name", VTOC(*vpp)->c_fileid);
		auto_candidate = 1;
	}
	
	if (cnode_locked)
		hfs_unlock(VTOC(*vpp));
exit:
	if (*vpp && fastdev_candidate && (*vpp)->v_parent == dvp && !(vnode_isfastdevicecandidate(*vpp))) {
		vnode_setfastdevicecandidate(*vpp);
		if (auto_candidate) {
			vnode_setautocandidate(*vpp);
		}
	}

	{
	uthread_t ut = (struct uthread *)get_bsdthread_info(current_thread());

	/*
	 * check to see if we issued any I/O while completing this lookup and
	 * this thread/task is throttleable... if so, throttle now
	 *
	 * this allows us to throttle in between multiple meta data reads that
	 * might result due to looking up a long pathname (since we'll have to
	 * re-enter hfs_vnop_lookup for each component of the pathnam not in
	 * the VFS cache), instead of waiting until the entire path lookup has
	 * completed and throttling at the systemcall return
	 */
	if (__improbable(ut->uu_lowpri_window)) {
		throttle_lowpri_io(1);
	}
	}

	return (error);
}


