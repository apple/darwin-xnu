/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)vfs_lookup.c	8.10 (Berkeley) 5/27/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/syslimits.h>
#include <sys/time.h>
#include <sys/namei.h>
#include <sys/vm.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/filedesc.h>
#include <sys/proc_internal.h>
#include <sys/kdebug.h>
#include <sys/unistd.h>		/* For _PC_NAME_MAX */
#include <sys/uio_internal.h>
#include <sys/kauth.h>

#include <bsm/audit_kernel.h>

#if KTRACE
#include <sys/ktrace.h>
#endif


static	void kdebug_lookup(struct vnode *dp, struct componentname *cnp);

/*
 * Convert a pathname into a pointer to a locked inode.
 *
 * The FOLLOW flag is set when symbolic links are to be followed
 * when they occur at the end of the name translation process.
 * Symbolic links are always followed for all other pathname
 * components other than the last.
 *
 * The segflg defines whether the name is to be copied from user
 * space or kernel space.
 *
 * Overall outline of namei:
 *
 *	copy in name
 *	get starting directory
 *	while (!done && !error) {
 *		call lookup to search path.
 *		if symbolic link, massage name in buffer and continue
 *	}
 */

int
namei(ndp)
	register struct nameidata *ndp;
{
	register struct filedesc *fdp;	/* pointer to file descriptor state */
	register char *cp;		/* pointer into pathname argument */
	register struct vnode *dp;	/* the directory we are searching */
	uio_t auio;
	int error;
	struct componentname *cnp = &ndp->ni_cnd;
	vfs_context_t ctx = cnp->cn_context;
	struct proc *p = vfs_context_proc(ctx);
	char *tmppn;
	char uio_buf[ UIO_SIZEOF(1) ];

#if DIAGNOSTIC
	if (!vfs_context_ucred(ctx) || !p)
		panic ("namei: bad cred/proc");
	if (cnp->cn_nameiop & (~OPMASK))
		panic ("namei: nameiop contaminated with flags");
	if (cnp->cn_flags & OPMASK)
		panic ("namei: flags contaminated with nameiops");
#endif
	fdp = p->p_fd;

	/*
	 * Get a buffer for the name to be translated, and copy the
	 * name into the buffer.
	 */
	if ((cnp->cn_flags & HASBUF) == 0) {
		cnp->cn_pnbuf = &ndp->ni_pathbuf;
		cnp->cn_pnlen = PATHBUFLEN;
	}
#if LP64_DEBUG
	if (IS_VALID_UIO_SEGFLG(ndp->ni_segflg) == 0) {
		panic("%s :%d - invalid ni_segflg\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

retry_copy:
	if (UIO_SEG_IS_USER_SPACE(ndp->ni_segflg))
		error = copyinstr(ndp->ni_dirp, cnp->cn_pnbuf,
			    cnp->cn_pnlen, (size_t *)&ndp->ni_pathlen);
	else
		error = copystr(CAST_DOWN(void *, ndp->ni_dirp), cnp->cn_pnbuf,
			    cnp->cn_pnlen, (size_t *)&ndp->ni_pathlen);

	if (error == ENAMETOOLONG && !(cnp->cn_flags & HASBUF)) {
	        MALLOC_ZONE(cnp->cn_pnbuf, caddr_t,
			    MAXPATHLEN, M_NAMEI, M_WAITOK);

		cnp->cn_flags |= HASBUF;
		cnp->cn_pnlen = MAXPATHLEN;
		
		goto retry_copy;
	}
	if (error)
	        goto error_out;

	/* If we are auditing the kernel pathname, save the user pathname */
	if (cnp->cn_flags & AUDITVNPATH1)
		AUDIT_ARG(upath, p, cnp->cn_pnbuf, ARG_UPATH1); 
	if (cnp->cn_flags & AUDITVNPATH2)
		AUDIT_ARG(upath, p, cnp->cn_pnbuf, ARG_UPATH2); 

	/*
	 * Do not allow empty pathnames
	 */
	if (*cnp->cn_pnbuf == '\0') {
		error = ENOENT;
	        goto error_out;
	}
	ndp->ni_loopcnt = 0;
#if KTRACE
	if (KTRPOINT(p, KTR_NAMEI))
		ktrnamei(p->p_tracep, cnp->cn_pnbuf);
#endif

	/*
	 * determine the starting point for the translation.
	 */
	if ((ndp->ni_rootdir = fdp->fd_rdir) == NULLVP) {
	        if ( !(fdp->fd_flags & FD_CHROOT))
		        ndp->ni_rootdir = rootvnode;
	}
	cnp->cn_nameptr = cnp->cn_pnbuf;

	ndp->ni_usedvp = NULLVP;

	if (*(cnp->cn_nameptr) == '/') {
	        while (*(cnp->cn_nameptr) == '/') {
		        cnp->cn_nameptr++;
			ndp->ni_pathlen--;
		}
		dp = ndp->ni_rootdir;
	} else if (cnp->cn_flags & USEDVP) {
	        dp = ndp->ni_dvp;
		ndp->ni_usedvp = dp;
	} else
	        dp = fdp->fd_cdir;

	if (dp == NULLVP) {
	        error = ENOENT;
		goto error_out;
	}
	ndp->ni_dvp = NULLVP;
	ndp->ni_vp  = NULLVP;

	for (;;) {
	        int need_newpathbuf;
		int linklen;

		ndp->ni_startdir = dp;

		if ( (error = lookup(ndp)) ) {
			goto error_out;
		}
		/*
		 * Check for symbolic link
		 */
		if ((cnp->cn_flags & ISSYMLINK) == 0) {
			return (0);
		}
		if ((cnp->cn_flags & FSNODELOCKHELD)) {
		        cnp->cn_flags &= ~FSNODELOCKHELD;
			unlock_fsnode(ndp->ni_dvp, NULL);
		}	
		if (ndp->ni_loopcnt++ >= MAXSYMLINKS) {
			error = ELOOP;
			break;
		}
		if (ndp->ni_pathlen > 1 || !(cnp->cn_flags & HASBUF))
		        need_newpathbuf = 1;
		else
		        need_newpathbuf = 0;

		if (need_newpathbuf) {
			MALLOC_ZONE(cp, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
		} else {
			cp = cnp->cn_pnbuf;
		}
		auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));

		uio_addiov(auio, CAST_USER_ADDR_T(cp), MAXPATHLEN);

		error = VNOP_READLINK(ndp->ni_vp, auio, ctx);
		if (error) {
			if (need_newpathbuf)
				FREE_ZONE(cp, MAXPATHLEN, M_NAMEI);
			break;
		}
		// LP64todo - fix this
		linklen = MAXPATHLEN - uio_resid(auio);
		if (linklen + ndp->ni_pathlen > MAXPATHLEN) {
			if (need_newpathbuf)
				FREE_ZONE(cp, MAXPATHLEN, M_NAMEI);

			error = ENAMETOOLONG;
			break;
		}
		if (need_newpathbuf) {
			long len = cnp->cn_pnlen;

			tmppn = cnp->cn_pnbuf;
			bcopy(ndp->ni_next, cp + linklen, ndp->ni_pathlen);
			cnp->cn_pnbuf = cp;
			cnp->cn_pnlen = MAXPATHLEN;

			if ( (cnp->cn_flags & HASBUF) )
			        FREE_ZONE(tmppn, len, M_NAMEI);
			else
			        cnp->cn_flags |= HASBUF;
		} else
			cnp->cn_pnbuf[linklen] = '\0';

		ndp->ni_pathlen += linklen;
		cnp->cn_nameptr = cnp->cn_pnbuf;

		/*
		 * starting point for 'relative'
		 * symbolic link path
		 */
		dp = ndp->ni_dvp;
	        /*
		 * get rid of references returned via 'lookup'
		 */
		vnode_put(ndp->ni_vp);
	        vnode_put(ndp->ni_dvp);

		ndp->ni_vp = NULLVP;
		ndp->ni_dvp = NULLVP;

		/*
		 * Check if symbolic link restarts us at the root
		 */
		if (*(cnp->cn_nameptr) == '/') {
			while (*(cnp->cn_nameptr) == '/') {
				cnp->cn_nameptr++;
				ndp->ni_pathlen--;
			}
			if ((dp = ndp->ni_rootdir) == NULLVP) {
			        error = ENOENT;
				goto error_out;
			}
		}
	}
	/*
	 * only come here if we fail to handle a SYMLINK...
	 * if either ni_dvp or ni_vp is non-NULL, then
	 * we need to drop the iocount that was picked
	 * up in the lookup routine
	 */
	if (ndp->ni_dvp)
	        vnode_put(ndp->ni_dvp);
	if (ndp->ni_vp)
	        vnode_put(ndp->ni_vp);
 error_out:
	if ( (cnp->cn_flags & HASBUF) ) {
	        cnp->cn_flags &= ~HASBUF;
		FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
	}
	cnp->cn_pnbuf = NULL;
	ndp->ni_vp = NULLVP;

	return (error);
}


/*
 * Search a pathname.
 * This is a very central and rather complicated routine.
 *
 * The pathname is pointed to by ni_ptr and is of length ni_pathlen.
 * The starting directory is taken from ni_startdir. The pathname is
 * descended until done, or a symbolic link is encountered. The variable
 * ni_more is clear if the path is completed; it is set to one if a
 * symbolic link needing interpretation is encountered.
 *
 * The flag argument is LOOKUP, CREATE, RENAME, or DELETE depending on
 * whether the name is to be looked up, created, renamed, or deleted.
 * When CREATE, RENAME, or DELETE is specified, information usable in
 * creating, renaming, or deleting a directory entry may be calculated.
 * If flag has LOCKPARENT or'ed into it, the parent directory is returned
 * locked. If flag has WANTPARENT or'ed into it, the parent directory is
 * returned unlocked. Otherwise the parent directory is not returned. If
 * the target of the pathname exists and LOCKLEAF is or'ed into the flag
 * the target is returned locked, otherwise it is returned unlocked.
 * When creating or renaming and LOCKPARENT is specified, the target may not
 * be ".".  When deleting and LOCKPARENT is specified, the target may be ".".
 * 
 * Overall outline of lookup:
 *
 * dirloop:
 *	identify next component of name at ndp->ni_ptr
 *	handle degenerate case where name is null string
 *	if .. and crossing mount points and on mounted filesys, find parent
 *	call VNOP_LOOKUP routine for next component name
 *	    directory vnode returned in ni_dvp, unlocked unless LOCKPARENT set
 *	    component vnode returned in ni_vp (if it exists), locked.
 *	if result vnode is mounted on and crossing mount points,
 *	    find mounted on vnode
 *	if more components of name, do next level at dirloop
 *	return the answer in ni_vp, locked if LOCKLEAF set
 *	    if LOCKPARENT set, return locked parent in ni_dvp
 *	    if WANTPARENT set, return unlocked parent in ni_dvp
 */
int
lookup(ndp)
	register struct nameidata *ndp;
{
	register char	*cp;		/* pointer into pathname argument */
	vnode_t		tdp;		/* saved dp */
	vnode_t		dp;		/* the directory we are searching */
	mount_t		mp;		/* mount table entry */
	int docache = 1;		/* == 0 do not cache last component */
	int wantparent;			/* 1 => wantparent or lockparent flag */
	int rdonly;			/* lookup read-only flag bit */
	int trailing_slash = 0;
	int dp_authorized = 0;
	int error = 0;
	struct componentname *cnp = &ndp->ni_cnd;
	vfs_context_t ctx = cnp->cn_context;

	/*
	 * Setup: break out flag bits into variables.
	 */
	if (cnp->cn_flags & (NOCACHE | DOWHITEOUT)) {
	        if ((cnp->cn_flags & NOCACHE) || (cnp->cn_nameiop == DELETE))
		        docache = 0;
	}
	wantparent = cnp->cn_flags & (LOCKPARENT | WANTPARENT);
	rdonly = cnp->cn_flags & RDONLY;
	cnp->cn_flags &= ~ISSYMLINK;
	cnp->cn_consume = 0;

	dp = ndp->ni_startdir;
	ndp->ni_startdir = NULLVP;

	cp = cnp->cn_nameptr;

	if (*cp == '\0') {
	        if ( (vnode_getwithref(dp)) ) {
			dp = NULLVP;
		        error = ENOENT;
			goto bad;
		}
		goto emptyname;
	}
dirloop: 
	ndp->ni_vp = NULLVP;

	if ( (error = cache_lookup_path(ndp, cnp, dp, ctx, &trailing_slash, &dp_authorized)) ) {
		dp = NULLVP;
		goto bad;
	}
	if ((cnp->cn_flags & ISLASTCN)) {
	        if (docache)
		        cnp->cn_flags |= MAKEENTRY;
	} else
	        cnp->cn_flags |= MAKEENTRY;

	dp = ndp->ni_dvp;

	if (ndp->ni_vp != NULLVP) {
	        /*
		 * cache_lookup_path returned a non-NULL ni_vp then,
		 * we're guaranteed that the dp is a VDIR, it's 
		 * been authorized, and vp is not ".."
		 */
	        goto returned_from_lookup_path;
	}

	/*
	 * Handle "..": two special cases.
	 * 1. If at root directory (e.g. after chroot)
	 *    or at absolute root directory
	 *    then ignore it so can't get out.
	 * 2. If this vnode is the root of a mounted
	 *    filesystem, then replace it with the
	 *    vnode which was mounted on so we take the
	 *    .. in the other file system.
	 */
	if ( (cnp->cn_flags & ISDOTDOT) ) {
		for (;;) {
		        if (dp == ndp->ni_rootdir || dp == rootvnode) {
			        ndp->ni_dvp = dp;
				ndp->ni_vp = dp;
				/*
				 * we're pinned at the root
				 * we've already got one reference on 'dp'
				 * courtesy of cache_lookup_path... take
				 * another one for the ".."
				 * if we fail to get the new reference, we'll
				 * drop our original down in 'bad'
				 */
				if ( (vnode_get(dp)) ) {
					error = ENOENT;
					goto bad;
				}
				goto nextname;
			}
			if ((dp->v_flag & VROOT) == 0 ||
			    (cnp->cn_flags & NOCROSSMOUNT))
			        break;
			if (dp->v_mount == NULL) {	/* forced umount */
			        error = EBADF;
				goto bad;
			}
			tdp = dp;
			dp = tdp->v_mount->mnt_vnodecovered;

			vnode_put(tdp);

			if ( (vnode_getwithref(dp)) ) {
			        dp = NULLVP;
				error = ENOENT;
				goto bad;
			}
			ndp->ni_dvp = dp;
			dp_authorized = 0;
		}
	}

	/*
	 * We now have a segment name to search for, and a directory to search.
	 */
unionlookup:
	ndp->ni_vp = NULLVP;

	if (dp->v_type != VDIR) {
	        error = ENOTDIR;
	        goto lookup_error;
	}
	if ( !(dp_authorized || (cnp->cn_flags & DONOTAUTH)) ) {
	        if ( (error = vnode_authorize(dp, NULL, KAUTH_VNODE_SEARCH, ctx)) )
		        goto lookup_error;
	}
	if ( (error = VNOP_LOOKUP(dp, &ndp->ni_vp, cnp, ctx)) ) {
lookup_error:
		if ((error == ENOENT) &&
		    (dp->v_flag & VROOT) && (dp->v_mount != NULL) &&
		    (dp->v_mount->mnt_flag & MNT_UNION)) {
		        if ((cnp->cn_flags & FSNODELOCKHELD)) {
			        cnp->cn_flags &= ~FSNODELOCKHELD;
				unlock_fsnode(dp, NULL);
			}	
			tdp = dp;
			dp = tdp->v_mount->mnt_vnodecovered;

			vnode_put(tdp);

			if ( (vnode_getwithref(dp)) ) {
			        dp = NULLVP;
				error = ENOENT;
				goto bad;
			}
			ndp->ni_dvp = dp;
			dp_authorized = 0;
			goto unionlookup;
		}

		if (error != EJUSTRETURN)
			goto bad;

		if (ndp->ni_vp != NULLVP)
			panic("leaf should be empty");

		/*
		 * If creating and at end of pathname, then can consider
		 * allowing file to be created.
		 */
		if (rdonly) {
			error = EROFS;
			goto bad;
		}
		if ((cnp->cn_flags & ISLASTCN) && trailing_slash && !(cnp->cn_flags & WILLBEDIR)) {
			error = ENOENT;
			goto bad;
		}
		/*
		 * We return with ni_vp NULL to indicate that the entry
		 * doesn't currently exist, leaving a pointer to the
		 * referenced directory vnode in ndp->ni_dvp.
		 */
		if (cnp->cn_flags & SAVESTART) {
			if ( (vnode_get(ndp->ni_dvp)) ) {
				error = ENOENT;
				goto bad;
			}
			ndp->ni_startdir = ndp->ni_dvp;
		}
		if (!wantparent)
		        vnode_put(ndp->ni_dvp);

		if (kdebug_enable)
		        kdebug_lookup(ndp->ni_dvp, cnp);
		return (0);
	}
returned_from_lookup_path:
	dp = ndp->ni_vp;

	/*
	 * Take into account any additional components consumed by
	 * the underlying filesystem.
	 */
	if (cnp->cn_consume > 0) {
		cnp->cn_nameptr += cnp->cn_consume;
		ndp->ni_next += cnp->cn_consume;
		ndp->ni_pathlen -= cnp->cn_consume;
		cnp->cn_consume = 0;
	} else {
	        if (dp->v_name == NULL || dp->v_parent == NULLVP) {
		        int isdot_or_dotdot;
			int  update_flags = 0;

			isdot_or_dotdot = (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') || (cnp->cn_flags & ISDOTDOT);
	    
			if (isdot_or_dotdot == 0) {
			        if (dp->v_name == NULL)
					update_flags |= VNODE_UPDATE_NAME;
				if (ndp->ni_dvp != NULLVP && dp->v_parent == NULLVP)
				        update_flags |= VNODE_UPDATE_PARENT;

				if (update_flags)
				        vnode_update_identity(dp, ndp->ni_dvp, cnp->cn_nameptr, cnp->cn_namelen, cnp->cn_hash, update_flags);
			}
		}

		if ( (cnp->cn_flags & MAKEENTRY) && (dp->v_flag & VNCACHEABLE) && LIST_FIRST(&dp->v_nclinks) == NULL) {
		        /*
			 * missing from name cache, but should
			 * be in it... this can happen if volfs
			 * causes the vnode to be created or the
			 * name cache entry got recycled but the
			 * vnode didn't...
			 * check to make sure that ni_dvp is valid
			 * cache_lookup_path may return a NULL
			 */
		        if (ndp->ni_dvp != NULL)
			        cache_enter(ndp->ni_dvp, dp, cnp);
		}
	}

	/*
	 * Check to see if the vnode has been mounted on...
	 * if so find the root of the mounted file system.
	 */
check_mounted_on:
	if ((dp->v_type == VDIR) && dp->v_mountedhere &&
            ((cnp->cn_flags & NOCROSSMOUNT) == 0)) {
	  
	        vnode_lock(dp);

		if ((dp->v_type == VDIR) && (mp = dp->v_mountedhere)) {

			mp->mnt_crossref++;
			vnode_unlock(dp);

			if (vfs_busy(mp, 0)) {
				mount_dropcrossref(mp, dp, 0);
				goto check_mounted_on;
			}
			error = VFS_ROOT(mp, &tdp, ctx);
			/*
			 * mount_dropcrossref does a vnode_put
			 * on dp if the 3rd arg is non-zero
			 */
			mount_dropcrossref(mp, dp, 1);
			dp = NULL;
			vfs_unbusy(mp);

			if (error) {
				goto bad2;
			}
			ndp->ni_vp = dp = tdp;
			
			goto check_mounted_on;
		} 
		vnode_unlock(dp);
	}

	/*
	 * Check for symbolic link
	 */
	if ((dp->v_type == VLNK) &&
	    ((cnp->cn_flags & FOLLOW) || trailing_slash || *ndp->ni_next == '/')) {
		cnp->cn_flags |= ISSYMLINK;
		return (0);
	}

	/*
	 * Check for bogus trailing slashes.
	 */
	if (trailing_slash) {
		if (dp->v_type != VDIR) {
			error = ENOTDIR;
			goto bad2;
		}
		trailing_slash = 0;
	}

nextname:
	/*
	 * Not a symbolic link.  If more pathname,
	 * continue at next component, else return.
	 */
	if (*ndp->ni_next == '/') {
		cnp->cn_nameptr = ndp->ni_next + 1;
		ndp->ni_pathlen--;
		while (*cnp->cn_nameptr == '/') {
			cnp->cn_nameptr++;
			ndp->ni_pathlen--;
		}
		vnode_put(ndp->ni_dvp);

		cp = cnp->cn_nameptr;

		if (*cp == '\0')
			goto emptyname;

		vnode_put(dp);
		goto dirloop;
	}
				  
	/*
	 * Disallow directory write attempts on read-only file systems.
	 */
	if (rdonly &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME)) {
		error = EROFS;
		goto bad2;
	}
	if (cnp->cn_flags & SAVESTART) {
	        /*	
		 * note that we already hold a reference
		 * on both dp and ni_dvp, but for some reason
		 * can't get another one... in this case we
		 * need to do vnode_put on dp in 'bad2'
		 */
	        if ( (vnode_get(ndp->ni_dvp)) ) {
		        error = ENOENT;
			goto bad2;
		}
		ndp->ni_startdir = ndp->ni_dvp;
	}
	if (!wantparent && ndp->ni_dvp)
		vnode_put(ndp->ni_dvp);

	if (cnp->cn_flags & AUDITVNPATH1)
		AUDIT_ARG(vnpath, dp, ARG_VNODE1);
	else if (cnp->cn_flags & AUDITVNPATH2)
		AUDIT_ARG(vnpath, dp, ARG_VNODE2);

	if (kdebug_enable)
	        kdebug_lookup(dp, cnp);
	return (0);

emptyname:
	cnp->cn_namelen = 0;
	/*
	 * A degenerate name (e.g. / or "") which is a way of
	 * talking about a directory, e.g. like "/." or ".".
	 */
	if (dp->v_type != VDIR) {
		error = ENOTDIR;
		goto bad;
	}
	if (cnp->cn_nameiop != LOOKUP) {
		error = EISDIR;
		goto bad;
	}
	if (wantparent) {
	        /*	
		 * note that we already hold a reference
		 * on dp, but for some reason can't
		 * get another one... in this case we
		 * need to do vnode_put on dp in 'bad'
		 */
	        if ( (vnode_get(dp)) ) {
		        error = ENOENT;
			goto bad;
		}
		ndp->ni_dvp = dp;
	}
	cnp->cn_flags &= ~ISDOTDOT;
	cnp->cn_flags |= ISLASTCN;
	ndp->ni_next = cp;
	ndp->ni_vp = dp;

	if (cnp->cn_flags & AUDITVNPATH1)
		AUDIT_ARG(vnpath, dp, ARG_VNODE1);
	else if (cnp->cn_flags & AUDITVNPATH2)
		AUDIT_ARG(vnpath, dp, ARG_VNODE2);
	if (cnp->cn_flags & SAVESTART)
		panic("lookup: SAVESTART");
	return (0);

bad2:
	if ((cnp->cn_flags & FSNODELOCKHELD)) {
	        cnp->cn_flags &= ~FSNODELOCKHELD;
		unlock_fsnode(ndp->ni_dvp, NULL);
	}
	if (ndp->ni_dvp)
	        vnode_put(ndp->ni_dvp);
	if (dp)
	        vnode_put(dp);
	ndp->ni_vp = NULLVP;

	if (kdebug_enable)
	        kdebug_lookup(dp, cnp);
	return (error);

bad:
	if ((cnp->cn_flags & FSNODELOCKHELD)) {
	        cnp->cn_flags &= ~FSNODELOCKHELD;
		unlock_fsnode(ndp->ni_dvp, NULL);
	}	
	if (dp)
	        vnode_put(dp);
	ndp->ni_vp = NULLVP;

	if (kdebug_enable)
	        kdebug_lookup(dp, cnp);
	return (error);
}

/*
 * relookup - lookup a path name component
 *    Used by lookup to re-aquire things.
 */
int
relookup(dvp, vpp, cnp)
	struct vnode *dvp, **vpp;
	struct componentname *cnp;
{
	struct vnode *dp = 0;		/* the directory we are searching */
	int wantparent;			/* 1 => wantparent or lockparent flag */
	int rdonly;			/* lookup read-only flag bit */
	int error = 0;
#ifdef NAMEI_DIAGNOSTIC
	int i, newhash;			/* DEBUG: check name hash */
	char *cp;			/* DEBUG: check name ptr/len */
#endif
	vfs_context_t ctx = cnp->cn_context;;

	/*
	 * Setup: break out flag bits into variables.
	 */
	wantparent = cnp->cn_flags & (LOCKPARENT|WANTPARENT);
	rdonly = cnp->cn_flags & RDONLY;
	cnp->cn_flags &= ~ISSYMLINK;

	if (cnp->cn_flags & NOCACHE)
	        cnp->cn_flags &= ~MAKEENTRY;
	else
	        cnp->cn_flags |= MAKEENTRY;

	dp = dvp;

	/*
	 * Check for degenerate name (e.g. / or "")
	 * which is a way of talking about a directory,
	 * e.g. like "/." or ".".
	 */
	if (cnp->cn_nameptr[0] == '\0') {
		if (cnp->cn_nameiop != LOOKUP || wantparent) {
			error = EISDIR;
			goto bad;
		}
		if (dp->v_type != VDIR) {
			error = ENOTDIR;
			goto bad;
		}
		if ( (vnode_get(dp)) ) {
		        error = ENOENT;
			goto bad;
		}
		*vpp = dp;

		if (cnp->cn_flags & SAVESTART)
			panic("lookup: SAVESTART");
		return (0);
	}
	/*
	 * We now have a segment name to search for, and a directory to search.
	 */
	if ( (error = VNOP_LOOKUP(dp, vpp, cnp, ctx)) ) {
		if (error != EJUSTRETURN)
			goto bad;
#if DIAGNOSTIC
		if (*vpp != NULL)
			panic("leaf should be empty");
#endif
		/*
		 * If creating and at end of pathname, then can consider
		 * allowing file to be created.
		 */
		if (rdonly) {
			error = EROFS;
			goto bad;
		}
		/*
		 * We return with ni_vp NULL to indicate that the entry
		 * doesn't currently exist, leaving a pointer to the
		 * (possibly locked) directory inode in ndp->ni_dvp.
		 */
		return (0);
	}
	dp = *vpp;

#if DIAGNOSTIC
	/*
	 * Check for symbolic link
	 */
	if (dp->v_type == VLNK && (cnp->cn_flags & FOLLOW))
		panic ("relookup: symlink found.\n");
#endif

	/*
	 * Disallow directory write attempts on read-only file systems.
	 */
	if (rdonly &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME)) {
		error = EROFS;
		goto bad2;
	}
	/* ASSERT(dvp == ndp->ni_startdir) */
	
	return (0);

bad2:
	vnode_put(dp);
bad:	
	*vpp = NULL;

	return (error);
}

/*
 * Free pathname buffer
 */
void
nameidone(struct nameidata *ndp)
{
	if ((ndp->ni_cnd.cn_flags & FSNODELOCKHELD)) {
	        ndp->ni_cnd.cn_flags &= ~FSNODELOCKHELD;
		unlock_fsnode(ndp->ni_dvp, NULL);
	}	
	if (ndp->ni_cnd.cn_flags & HASBUF) {
		char *tmp = ndp->ni_cnd.cn_pnbuf;

		ndp->ni_cnd.cn_pnbuf = NULL;
		ndp->ni_cnd.cn_flags &= ~HASBUF;
		FREE_ZONE(tmp, ndp->ni_cnd.cn_pnlen, M_NAMEI);
	}
}


#define NUMPARMS 23

static void
kdebug_lookup(dp, cnp)
	struct vnode *dp;
	struct componentname *cnp;
{
	register unsigned int i, n;
	register int dbg_namelen;
	register int save_dbg_namelen;
	register char *dbg_nameptr;
	long dbg_parms[NUMPARMS];
	char dbg_buf[4];
	static char *dbg_filler = ">>>>";

	/* Collect the pathname for tracing */
	dbg_namelen = (cnp->cn_nameptr - cnp->cn_pnbuf) + cnp->cn_namelen;
	dbg_nameptr = cnp->cn_nameptr + cnp->cn_namelen;

	if (dbg_namelen > sizeof(dbg_parms))
	    dbg_namelen = sizeof(dbg_parms);
	dbg_nameptr -= dbg_namelen;
	save_dbg_namelen = dbg_namelen;

	i = 0;

	while (dbg_namelen > 0) {
	    if (dbg_namelen >= 4) {
	        dbg_parms[i++] = *(long *)dbg_nameptr;
		dbg_nameptr += sizeof(long);
		dbg_namelen -= sizeof(long);
	    } else {
	        for (n = 0; n < dbg_namelen; n++)
		    dbg_buf[n] = *dbg_nameptr++;
		while (n <= 3) {
		    if (*dbg_nameptr)
		        dbg_buf[n++] = '>';
		    else
		        dbg_buf[n++] = 0;
		}
		dbg_parms[i++] = *(long *)&dbg_buf[0];

		break;
	    }
	}
	while (i < NUMPARMS) {
	    if (*dbg_nameptr)
	        dbg_parms[i++] = *(long *)dbg_filler;
	    else
	        dbg_parms[i++] = 0;
	}

	/*
	  In the event that we collect multiple, consecutive pathname
	  entries, we must mark the start of the path's string.
	*/
	KERNEL_DEBUG_CONSTANT((FSDBG_CODE(DBG_FSRW,36)) | DBG_FUNC_START,
		(unsigned int)dp, dbg_parms[0], dbg_parms[1], dbg_parms[2], 0);

	for (dbg_namelen = save_dbg_namelen-12, i=3;
	     dbg_namelen > 0;
	     dbg_namelen -=(4 * sizeof(long)), i+= 4)
	  {
	    KERNEL_DEBUG_CONSTANT((FSDBG_CODE(DBG_FSRW,36)) | DBG_FUNC_NONE,
				  dbg_parms[i], dbg_parms[i+1], dbg_parms[i+2], dbg_parms[i+3], 0);
	  }
}
