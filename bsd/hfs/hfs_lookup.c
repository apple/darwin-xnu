/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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
 *
 *	MODIFICATION HISTORY:
 *	21-May-1999 Don Brady		Add support for HFS rooting.
 *      25-Feb-1999 Clark Warner	Fixed the error case of VFS_VGGET when
 *                                      processing DotDot (..) to relock parent
 *	23-Feb-1999 Pat Dirks		Finish cleanup around Don's last fix in "." and ".." handling.
 *	11-Nov-1998 Don Brady		Take out VFS_VGET that got added as part of previous fix.
 *	14-Oct-1998 Don Brady		Fix locking policy volation in hfs_lookup for ".." case
 *								(radar #2279902).
 *	 4-Jun-1998 Pat Dirks		Split off from hfs_vnodeops.c
 */

#include <sys/param.h>
#include <sys/namei.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/paths.h>

#include	"hfs.h"
#include	"hfs_dbg.h"
#include	"hfscommon/headers/FileMgrInternal.h"

u_int16_t	GetForkFromName(struct componentname  *cnp);
int			hfs_vget_sibling(struct vnode *vdp, u_int16_t forkType, struct vnode **vpp);
int 		hfs_vget_catinfo(struct vnode *parent_vp, struct hfsCatalogInfo *catInfo, u_int32_t forkType, struct vnode **target_vpp);

/*
 *	XXX SER fork strings.
 * Put these someplace better
 */
#define gHFSForkIdentStr	"/"
#define gDataForkNameStr	"data"
#define gRsrcForkNameStr	"rsrc"


#if DBG_VOP_TEST_LOCKS
extern void DbgVopTest(int maxSlots, int retval, VopDbgStoreRec *VopDbgStore, char *funcname);
#endif

/*****************************************************************************
*
*	Operations on vnodes
*
*****************************************************************************/


/*	
 * FROM FREEBSD 3.1
 * Convert a component of a pathname into a pointer to a locked hfsnode.
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
 * If flag has LOCKPARENT or'ed into it and the target of the pathname
 * exists, lookup returns both the target and its parent directory locked.
 * When creating or renaming and LOCKPARENT is specified, the target may
 * not be ".".	When deleting and LOCKPARENT is specified, the target may
 * be "."., but the caller must check to ensure it does an vrele and vput
 * instead of two vputs.
 *
 * LOCKPARENT and WANTPARENT actually refer to the parent of the last item,
 * so if ISLASTCN is not set, they should be ignored. Also they are mutually exclusive, or
 * WANTPARENT really implies DONTLOCKPARENT. Either of them set means that the calling
 * routine wants to access the parent of the target, locked or unlocked.
 *
 * Keeping the parent locked as long as possible protects from other processes
 * looking up the same item, so it has to be locked until the hfsnode is totally finished
 *
 * This routine is actually used as VOP_CACHEDLOOKUP method, and the
 * filesystem employs the generic hfs_cache_lookup() as VOP_LOOKUP
 * method.
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
 *	return VOP_CACHEDLOOKUP()
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
 *	  inode and return info to allow rewrite
 *	if not at end, add name to cache; if at end and neither creating
 *	  nor deleting, add name to cache
 */

/*	
 *	Lookup *nm in directory *pvp, return it in *a_vpp.
 *	**a_vpp is held on exit.
 *	We create a hfsnode for the file, but we do NOT open the file here.

#% lookup	dvp L ? ?
#% lookup	vpp - L -

	IN struct vnode *dvp - Parent node of file;
	INOUT struct vnode **vpp - node of target file, its a new node if the target vnode did not exist;
	IN struct componentname *cnp - Name of file;

 *	When should we lock parent_hp in here ??
 */

int
hfs_lookup(ap)
	struct vop_cachedlookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{
	struct vnode					*parent_vp;
	struct vnode					*target_vp;
	struct vnode					*tparent_vp;
	struct hfsnode					*parent_hp;				/* parent */
	struct componentname			*cnp;
	struct ucred					*cred;
	struct proc						*p;
	struct hfsCatalogInfo			catInfo;
	u_int32_t						parent_id;
	u_int32_t						nodeID;
	u_int16_t						targetLen;
	u_int16_t						forkType;
	int 							flags;
	int								lockparent;						/* !0 => lockparent flag is set */
	int								wantparent;						/* !0 => wantparent or lockparent flag */
	int								nameiop;
	int								retval;
	u_char							isDot, isDotDot, found;
	DBG_FUNC_NAME("lookup");
	DBG_VOP_LOCKS_DECL(2);
	DBG_VOP_LOCKS_INIT(0,ap->a_dvp, VOPDBG_LOCKED, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_POS);
	DBG_VOP_LOCKS_INIT(1,*ap->a_vpp, VOPDBG_IGNORE, VOPDBG_LOCKED, VOPDBG_IGNORE, VOPDBG_POS);
	DBG_VOP_PRINT_FUNCNAME();DBG_VOP_CONT(("\n"));
	DBG_HFS_NODE_CHECK(ap->a_dvp);


	/*
	 * Do initial setup
	 */
        INIT_CATALOGDATA(&catInfo.nodeData, 0);
	parent_vp		= ap->a_dvp;
	cnp				= ap->a_cnp;
	parent_hp		= VTOH(parent_vp);				/* parent */
	target_vp		= NULL;
	targetLen		= cnp->cn_namelen;
	nameiop			= cnp->cn_nameiop;
	cred			= cnp->cn_cred;
	p				= cnp->cn_proc;
	lockparent		= cnp->cn_flags & LOCKPARENT;
	wantparent		= cnp->cn_flags & (LOCKPARENT|WANTPARENT);
	flags 			= cnp->cn_flags;
	parent_id		= H_FILEID(parent_hp);
	nodeID			= kUnknownID;
	found 			= FALSE;
	isDot			= FALSE;
	isDotDot		= FALSE;
	retval			= E_NONE;
	forkType		= kUndefinedFork;


	/*
	 * We now have a segment name to search for, and a directory to search.
	 *
	 */

	/*
	 * First check to see if it is a . or .., else look it up.
	 */

	if (flags & ISDOTDOT) {									/* Wanting the parent */
		isDotDot = TRUE;
		found = TRUE;										/* .. is always defined */
		nodeID = H_DIRID(parent_hp);
	}														/* Wanting ourselves */
	else if ((cnp->cn_nameptr[0] == '.') && (targetLen == 1)) {
		isDot = TRUE;
		found = TRUE;										/* We always know who we are */
	} 
	else {													/* Wanting something else */
		catInfo.hint = kNoHint;

		/* lock catalog b-tree */
		retval = hfs_metafilelocking(VTOHFS(parent_vp), kHFSCatalogFileID, LK_SHARED, p);
		if (retval)
			   goto Err_Exit;

		retval = hfs_getcatalog (VTOVCB(parent_vp), parent_id, cnp->cn_nameptr, targetLen, &catInfo);
	
	/* unlock catalog b-tree */
		(void) hfs_metafilelocking(VTOHFS(parent_vp), kHFSCatalogFileID, LK_RELEASE, p);
	
		if (retval == E_NONE)
			found = TRUE;
	};


	/*
	 * At this point we know IF we have a valid dir/name.
	 */


	retval = E_NONE;
	if (! found) {
	/*
	 * This is a non-existing entry
	 *
	 * If creating, and at end of pathname and current
	 * directory has not been removed, then can consider
	 * allowing file to be created.
	 */
	if ((nameiop == CREATE || nameiop == RENAME ||
		 	(nameiop == DELETE &&
		  	(ap->a_cnp->cn_flags & DOWHITEOUT) &&
		  	(ap->a_cnp->cn_flags & ISWHITEOUT))) &&
			(flags & ISLASTCN)) {
		/*
		 * Access for write is interpreted as allowing
		 * creation of files in the directory.
		 */
		retval = VOP_ACCESS(parent_vp, VWRITE, cred, cnp->cn_proc);
		if (retval)
			return (retval);
	
		cnp->cn_flags |= SAVENAME;
		if (!lockparent)
			VOP_UNLOCK(parent_vp, 0, p);
		retval = EJUSTRETURN;
		goto Err_Exit;
		}
	
		/*
		 * Insert name into cache (as non-existent) if appropriate.
		 */

		/*
		* XXX SER - Here we would store the name in cache as non-existant if not trying to create it, but,
	* the name cache IS case-sensitive, thus maybe showing a negative hit, when the name
	* is only different by case. So hfs does not support negative caching. Something to look at.
	* (See radar 2293594 for a failed example)
		if ((cnp->cn_flags & MAKEENTRY) && nameiop != CREATE)
			cache_enter(parent_vp, *vpp, cnp);
		*/
	
		retval = ENOENT;
	}
	else {
		/*
		 * We have found an entry
		 *
		 * Here we have to decide what type of vnode to create.
		 * There are 3 type of objects that are given:
		 * 1. '.': return the same dp
		 * 2. '..' return the parent of dp, always a VDIR
		 * 3. catinfo rec: return depending on type:
		 *  A. VDIR, nodeType is kCatalogFolderNode
		 *  B. VLINK nodeType is kCatalogFileNode, the mode is IFLNK (esp. if it is a link to a directory e.g. bar/link/foo)
		 *  C. VREG, nodeType is kCatalogFileNode, forkType at this point is unknown
		 * To determine the forkType, we can use this algorithm (\0 in the strings mean the NULL character):
		 * a. forkType is kDataType iff ISLASTCN is set (as in the case of the default fork e.g. data/foo).
		 * b. forkType is kDataType iff ISLASTCN is not set and the namePtr is followed by "/?AppleHFSFork/data\0"
		 * c. forkType is kRsrcType iff ISLASTCN is not set and the namePtr is followed by "/?AppleHFSFork/rsrc\0"
		 * If the latter two are correct, then we 'consume' the remaining of the name buffer
		 * and set the cnp as appropriate.
		 * Anything else returns an retval
		 */

		
		/*
		 * If deleting, and at end of pathname, return
		 * parameters which can be used to remove file.
		 * If the wantparent flag isn't set, we return only
		 * the directory (in ndp->ndvp), otherwise we go
		 * on and lock the hfsnode, being careful with ".".
		 *
		 * Forks cannot be deleted so scan-ahead is illegal, so just return the default fork
		 */
		if (nameiop == DELETE && (flags & ISLASTCN)) {
			/*
			* Write access to directory required to delete files.
			*/
			retval = VOP_ACCESS(parent_vp, VWRITE, cred, cnp->cn_proc);
			if (retval)
				goto Err_Exit;
	
			if (isDot) {					/* Want to return ourselves */
				VREF(parent_vp);
				target_vp = parent_vp;
				goto Err_Exit;
			}
			else if (isDotDot) {
				retval = VFS_VGET(parent_vp->v_mount, &nodeID, &target_vp);
				if (retval)
					goto Err_Exit;
			}
			else {
				retval = hfs_vget_catinfo(parent_vp, &catInfo, kDefault, &target_vp);
				if (retval)
					goto Err_Exit;
				CLEAN_CATALOGDATA(&catInfo.nodeData);
			};


			/*
			 * If directory is "sticky", then user must own
			 * the directory, or the file in it, else she
			 * may not delete it (unless she's root). This
			 * implements append-only directories.
			 */
			if ((parent_hp->h_meta->h_mode & ISVTX) &&
				(cred->cr_uid != 0) &&
				(cred->cr_uid != parent_hp->h_meta->h_uid) &&
				(target_vp->v_type != VLNK) &&
				(hfs_owner_rights(target_vp, cred, p, false))) {
				vput(target_vp);
				retval = EPERM;
				goto Err_Exit;
			}
#if HFS_HARDLINKS
			/*
			 * If this is a link node then we need to save the name
			 * (of the link) so we can delete it from the catalog b-tree.
			 * In this case, hfs_remove will then free the component name.
			 */
			if (target_vp && (VTOH(target_vp)->h_meta->h_metaflags & IN_DATANODE))
				cnp->cn_flags |= SAVENAME;
#endif
	  
			if (!lockparent)
				VOP_UNLOCK(parent_vp, 0, p);
			goto Err_Exit;
		 };
	
		/*
		 * If rewriting 'RENAME', return the hfsnode and the
		 * information required to rewrite the present directory
		 */
		if (nameiop == RENAME && wantparent && (cnp->cn_flags & ISLASTCN)) {
	
			if ((retval = VOP_ACCESS(parent_vp, VWRITE, cred, cnp->cn_proc)) != 0)
				goto Err_Exit;

			/*
			 * Careful about locking second inode.
			 * This can only occur if the target is ".". like 'mv foo/bar foo/.'
			 */
			if (isDot) {
				retval = EISDIR;
				goto Err_Exit;
			}
			else if (isDotDot) {
				retval = VFS_VGET(parent_vp->v_mount, &nodeID, &target_vp);
				if (retval)
					goto Err_Exit;
			}
            else {

                retval = hfs_vget_catinfo(parent_vp, &catInfo, kDefault, &target_vp);
                if (retval)
                    goto Err_Exit;

                CLEAN_CATALOGDATA(&catInfo.nodeData);	/* Should do nothing */
            };
			
			cnp->cn_flags |= SAVENAME;
			if (!lockparent)
				VOP_UNLOCK(parent_vp, 0, p);

			goto Err_Exit;
		/* Finished...all is well, goto the end */
		 };

		/*
		 * Step through the translation in the name.  We do not `vput' the
		 * directory because we may need it again if a symbolic link
		 * is relative to the current directory.  Instead we save it
		 * unlocked as "tparent_vp".  We must get the target hfsnode before unlocking
		 * the directory to insure that the hfsnode will not be removed
		 * before we get it.  We prevent deadlock by always fetching
		 * inodes from the root, moving down the directory tree. Thus
		 * when following backward pointers ".." we must unlock the
		 * parent directory before getting the requested directory.
		 * There is a potential race condition here if both the current
		 * and parent directories are removed before the VFS_VGET for the
		 * hfsnode associated with ".." returns.  We hope that this occurs
		 * infrequently since we cannot avoid this race condition without
		 * implementing a sophisticated deadlock detection algorithm.
		 * Note also that this simple deadlock detection scheme will not
		 * work if the file system has any hard links other than ".."
		 * that point backwards in the directory structure.
		 */
	
		tparent_vp = parent_vp;
		if (isDotDot) {
			VOP_UNLOCK(tparent_vp, 0, p);	/* race to get the inode */
			if ((retval = VFS_VGET(parent_vp->v_mount, &nodeID, &target_vp))) {
			vn_lock(tparent_vp, LK_EXCLUSIVE | LK_RETRY, p);
			goto Err_Exit;
		}
			if (lockparent && (flags & ISLASTCN) && (tparent_vp != target_vp) && 
			    (retval = vn_lock(tparent_vp, LK_EXCLUSIVE, p))) {
				vput(target_vp);
				goto Err_Exit;
			}
		}
		else if (isDot) {
			VREF(parent_vp);	/* we want ourself, ie "." */
			target_vp = parent_vp;
		}
		else {
			mode_t mode;
			/* 
			 * Determine what fork to get, currenty 3 scenarios are supported:
			 * 1. ./foo: if it is a dir, return a VDIR else return data fork
			 * 2. ./foo/.__Fork/data: return data fork
			 * 3. ./foo/.__Fork/rsrc: return resource fork
			 * So the algorithm is:
			 * If the object is a directory
			 *	then return a VDIR vnode
			 * else if ISLASTCN is true
			 * 	then get the vnode with forkType=kDataFork
			 * else
			 *	compare with the remaining cnp buffer with "/.__Fork/"
			 *	if a match
			 * 		then compare string after that with either 'data' or 'rsrc'
			 *		if match
			 *			then 
			 *			'consume' rest of cnp, setting appropriate values and flags
			 *			return vnode depending on match
			 *		else
			 *			bad fork name
			 *	else
			 *		illegal path after a file object
			 */

			mode = (mode_t)(catInfo.nodeData.cnd_mode);
			
			if (catInfo.nodeData.cnd_type == kCatalogFolderNode) {
				forkType = kDirectory;				/* Really ignored */
			} 
			else if ((mode & IFMT) == IFLNK) {
				forkType = kDataFork;
			}									/* After this point, nodeType should be a file */
			else if (flags & ISLASTCN) {			/* Create a default fork */
				forkType = kDataFork;
		}
			else {									/* determine what fork was specified */
				forkType = GetForkFromName(cnp);
				flags |= ISLASTCN;					/* To know to unlock the parent if needed */
			};	/* else */

			
			/* If couldn't determine what type of fork, leave */
			if (forkType == kUndefinedFork) {				
				retval = ENOTDIR;
				goto Err_Exit;
			};
				
			/* Get the vnode now that what type of fork is known */
			DBG_ASSERT((forkType==kDirectory) || (forkType==kDataFork) || (forkType==kRsrcFork));
			retval = hfs_vget_catinfo(tparent_vp, &catInfo, forkType, &target_vp);
			if (retval != E_NONE)
				goto Err_Exit;

			if (!lockparent || !(flags & ISLASTCN))
				VOP_UNLOCK(tparent_vp, 0, p);

			CLEAN_CATALOGDATA(&catInfo.nodeData);

		};	/* else found */


		/*
		* Insert name in cache if wanted.
		 * Names with composed chars are not put into the name cache.
		 * Resource forks are not entered in the name cache. This
		 * avoids deadlocks.
		 */
		if ((cnp->cn_flags & MAKEENTRY)
		    && (cnp->cn_namelen == catInfo.nodeData.cnm_length)
			&& ((H_FORKTYPE(VTOH(target_vp))) != kRsrcFork))	{
			/*
			 * XXX SER - Might be good idea to bcopy(catInfo.nodeData.fsspec.name, cnp->cn_nameptr)
			 * to "normalize" the name cache. This will avoid polluting the name cache with
			 * names that are different in case, and allow negative caching
			 */
			cache_enter(parent_vp, target_vp, cnp);
			}
	


	};	/* else found == TRUE */
	
Err_Exit:

	CLEAN_CATALOGDATA(&catInfo.nodeData);		/* Just to make sure */
	*ap->a_vpp = target_vp;

	DBG_VOP_UPDATE_VP(1, *ap->a_vpp);
	//DBG_VOP_LOOKUP_TEST (funcname, cnp, parent_vp, target_vp);
	//DBG_VOP_LOCKS_TEST(E_NONE);

	return (retval);
}



/*
 * Based on vn_cache_lookup (which is vfs_cache_lookup in FreeBSD 3.1)
 *
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
 * In hfs, since a name can represent multiple forks, it cannot
 * be known what fork the name matches, so further checks have to be done.
 * Currently a policy of first requested, is the one stored, is followed.
 *
 * SER XXX If this proves inadequate maybe we can munge the name to contain a fork reference
 * like foo -> foo.d for the data fork.
 */

int
hfs_cache_lookup(ap)
	struct vop_lookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{
	struct vnode *vdp;
	struct vnode *pdp;
	int lockparent; 
	int error;
	struct vnode **vpp = ap->a_vpp;
	struct componentname    *cnp = ap->a_cnp;
	struct ucred            *cred = cnp->cn_cred;
	int flags = cnp->cn_flags;
	struct proc             *p = cnp->cn_proc;
	struct hfsnode          *hp;
	u_int32_t vpid;	/* capability number of vnode */
	DBG_FUNC_NAME("cache_lookup");
	DBG_VOP_LOCKS_DECL(2);
	DBG_VOP_LOCKS_INIT(0,ap->a_dvp, VOPDBG_LOCKED, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_POS);
	DBG_VOP_LOCKS_INIT(1,*ap->a_vpp, VOPDBG_IGNORE, VOPDBG_LOCKED, VOPDBG_IGNORE, VOPDBG_POS);
	DBG_VOP_PRINT_FUNCNAME();DBG_VOP_CONT(("\n"));
    DBG_VOP_CONT(("\tTarget: "));DBG_VOP_PRINT_CPN_INFO(ap->a_cnp);DBG_VOP_CONT(("\n"));
	DBG_HFS_NODE_CHECK(ap->a_dvp);

	*vpp = NULL;
	vdp = ap->a_dvp;
	lockparent = flags & LOCKPARENT;

	if (vdp->v_type != VDIR)
		return (ENOTDIR);

	if ((flags & ISLASTCN) && (vdp->v_mount->mnt_flag & MNT_RDONLY) &&
		(cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME))
		return (EROFS);

	error = VOP_ACCESS(vdp, VEXEC, cred, cnp->cn_proc);

	if (error)
		return (error);

	/*
	 * Lookup an entry in the cache
	 * If the lookup succeeds, the vnode is returned in *vpp, and a status of -1 is
	 * returned. If the lookup determines that the name does not exist
	 * (negative cacheing), a status of ENOENT is returned. If the lookup
	 * fails, a status of zero is returned.
	 */
	error = cache_lookup(vdp, vpp, cnp);

	if (error == 0)  {		/* Unsuccessfull */
		DBG_VOP(("\tWas not in name cache\n"));
		error = hfs_lookup(ap);
#if HFS_HARDLINKS
		if (error)
			return (error);
		/*
		 * If this is a hard-link vnode then we need to update
		 * the name (of the link) and update the parent ID. This
		 * enables getattrlist calls to return correct link info.
		 */
		hp = VTOH(*ap->a_vpp);
		if ((flags & ISLASTCN) && (hp->h_meta->h_metaflags & IN_DATANODE)) {
			H_DIRID(hp) = H_FILEID(VTOH(ap->a_dvp));
			hfs_set_metaname(cnp->cn_nameptr, hp->h_meta, HTOHFS(hp));
		}
#endif
		return (error);
	};
	
	DBG_VOP(("\tName was found in the name cache"));
	if (error == ENOENT) {
		DBG_VOP_CONT((" though it was a NEGATIVE HIT\n"));
		return (error);
	};
	DBG_VOP_CONT(("\n"));
	
#if HFS_HARDLINKS
	/*
	 * If this is a hard-link vnode then we need to update
	 * the name (of the link) and update the parent ID. This
	 * enables getattrlist calls to return correct link info.
	 */
	hp = VTOH(*vpp);
	if ((flags & ISLASTCN) && (hp->h_meta->h_metaflags & IN_DATANODE)) {
		H_DIRID(hp) = H_FILEID(VTOH(vdp));
		hfs_set_metaname(cnp->cn_nameptr, hp->h_meta, HTOHFS(hp));
	}
#endif

	/* We have a name that matched */
	pdp = vdp;
	vdp = *vpp;
	vpid = vdp->v_id;
	if (pdp == vdp) {	/* lookup on "." */
		VREF(vdp);
		error = 0;
	} else if (flags & ISDOTDOT) {
		/* 
		 * Carefull on the locking policy,
		 * remember we always lock from parent to child, so have
		 * to release lock on child before trying to lock parent
		 * then regain lock if needed
		 */
		VOP_UNLOCK(pdp, 0, p);
		error = vget(vdp, LK_EXCLUSIVE, p);
		if (!error && lockparent && (flags & ISLASTCN))
			error = vn_lock(pdp, LK_EXCLUSIVE, p);
	} else if ((! (flags & ISLASTCN)) && (vdp->v_type == VREG) && 
				(GetForkFromName(cnp) != kDataFork)) {
		/* 
		 * We only store data forks in the name cache.
		 */				 
		goto finished;
	} else {
		error = vget(vdp, LK_EXCLUSIVE, p);
		if (!lockparent || error || !(flags & ISLASTCN))
			VOP_UNLOCK(pdp, 0, p);
	}
	/*
	 * Check that the capability number did not change
	 * while we were waiting for the lock.
	 */
	if (!error) {
		if (vpid == vdp->v_id)
			return (0);		/* HERE IS THE NORMAL EXIT FOR CACHE LOOKUP!!!! */
		/*
		 * The above is the NORMAL exit, after this point is an error
		 * condition.
		 */
		vput(vdp);
		if (lockparent && pdp != vdp && (flags & ISLASTCN))
			VOP_UNLOCK(pdp, 0, p);
	}
	error = vn_lock(pdp, LK_EXCLUSIVE, p);
	if (error)
		return (error);

finished:

	return (hfs_lookup(ap));
}

/*
 *	Parses a componentname and sees if the remaining path
 *	contains a hfs named fork specifier. If it does set the
 *	componentname to consume the rest of the path, and
 *	return the forkType
 */

u_int16_t	GetForkFromName(struct componentname  *cnp)
{
	u_int16_t	forkType 	= kUndefinedFork;
	char		*tcp 		= cnp->cn_nameptr + cnp->cn_namelen;

	if (bcmp(tcp, _PATH_FORKSPECIFIER, sizeof(_PATH_FORKSPECIFIER) - 1) == 0) {		
		/* Its a HFS fork, so far */
		tcp += (sizeof(_PATH_FORKSPECIFIER) - 1);
		if (bcmp(tcp, _PATH_DATANAME, sizeof(_PATH_DATANAME)) == 0) {
			forkType = kDataFork;
			cnp->cn_consume = sizeof(_PATH_FORKSPECIFIER) + sizeof(_PATH_DATANAME) - 2;
		}
		else if (bcmp(tcp, _PATH_RSRCNAME, sizeof(_PATH_RSRCNAME)) == 0) {
			forkType = kRsrcFork;
			cnp->cn_consume = sizeof(_PATH_FORKSPECIFIER) + sizeof(_PATH_RSRCNAME) - 2;
		};	/* else if */
	};	/* if bcmp */	


	/* XXX SER For backwards compatability...keep it */
	if (forkType == kUndefinedFork) {
		tcp = cnp->cn_nameptr + cnp->cn_namelen;
	if (bcmp(tcp, gHFSForkIdentStr, sizeof(gHFSForkIdentStr) - 1) == 0) {		
		/* Its a HFS fork, so far */
		tcp += (sizeof(gHFSForkIdentStr) - 1);
		if (bcmp(tcp, gDataForkNameStr, sizeof(gDataForkNameStr)) == 0) {
			forkType = kDataFork;
			cnp->cn_consume = sizeof(gHFSForkIdentStr) + sizeof(gDataForkNameStr) - 2;
		}
		else if (bcmp(tcp, gRsrcForkNameStr, sizeof(gRsrcForkNameStr)) == 0) {
			forkType = kRsrcFork;
			cnp->cn_consume = sizeof(gHFSForkIdentStr) + sizeof(gRsrcForkNameStr) - 2;
		};	/* else if */
	};	/* if bcmp */								
	};							

	return forkType;	
}

#if DBG_VOP_TEST_LOCKS

void DbgLookupTest( char *funcname, struct componentname  *cnp, struct vnode *dvp, struct vnode *vp)
{
	if (! (hfs_dbg_lookup || hfs_dbg_all))
		return;
		
		
	if (dvp) {
		if (lockstatus(&VTOH(dvp)->h_lock)) {
			DBG_LOOKUP (("%s: Parent vnode exited LOCKED", funcname));
		}
		else {
			DBG_LOOKUP (("%s: Parent vnode exited UNLOCKED", funcname));
		}
	}

	if (vp) {
		if (vp==dvp)
		  {
			DBG_LOOKUP (("%s: Target and Parent are the same", funcname));
		  }
		else {
			if (lockstatus(&VTOH(vp)->h_lock)) {
				DBG_LOOKUP (("%s: Found vnode exited LOCKED", funcname));
			}
			else {
				DBG_LOOKUP (("%s: Found vnode exited LOCKED", funcname));
			}
		}
		DBG_LOOKUP (("%s: Found vnode 0x%x has vtype of %d\n ", funcname, (u_int)vp, vp->v_type));
	}
	else
		DBG_LOOKUP (("%s: Found vnode exited NULL\n",  funcname));


}

#endif /* DBG_VOP_TEST_LOCKS */

