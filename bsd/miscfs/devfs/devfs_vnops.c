/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright 1997,1998 Julian Elischer.  All rights reserved.
 * julian@freebsd.org
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * devfs_vnops.c
 */

/*
 * HISTORY
 *  Clark Warner (warner_c@apple.com) Tue Feb 10 2000
 *  - Added err_copyfile to the vnode operations table
 *  Dieter Siegmund (dieter@apple.com) Thu Apr  8 14:08:19 PDT 1999
 *  - instead of duplicating specfs here, created a vnode-ops table
 *    that redirects most operations to specfs (as is done with ufs);
 *  - removed routines that made no sense
 *  - cleaned up reclaim: replaced devfs_vntodn() with a macro VTODN()
 *  - cleaned up symlink, link locking
 *  - added the devfs_lock to protect devfs data structures against
 *    driver's calling devfs_add_devswf()/etc.
 *  Dieter Siegmund (dieter@apple.com) Wed Jul 14 13:37:59 PDT 1999
 *  - free the devfs devnode in devfs_inactive(), not just in devfs_reclaim()
 *    to free up kernel memory as soon as it's available
 *  - got rid of devfsspec_{read, write}
 *  Dieter Siegmund (dieter@apple.com) Fri Sep 17 09:58:38 PDT 1999
 *  - update the mod/access times
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/namei.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/disklabel.h>
#include <sys/lock.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <miscfs/specfs/specdev.h>
#include <sys/dirent.h>
#include <sys/vmmeter.h>
#include <sys/vm.h>

#include "devfsdefs.h"

/*
 * Convert a component of a pathname into a pointer to a locked node.
 * This is a very central and rather complicated routine.
 * If the file system is not maintained in a strict tree hierarchy,
 * this can result in a deadlock situation (see comments in code below).
 *
 * The flag argument is LOOKUP, CREATE, RENAME, or DELETE depending on
 * whether the name is to be looked up, created, renamed, or deleted.
 * When CREATE, RENAME, or DELETE is specified, information usable in
 * creating, renaming, or deleting a directory entry may be calculated.
 * If flag has LOCKPARENT or'ed into it and the target of the pathname
 * exists, lookup returns both the target and its parent directory locked.
 * When creating or renaming and LOCKPARENT is specified, the target may
 * not be ".".  When deleting and LOCKPARENT is specified, the target may
 * be "."., but the caller must check to ensure it does an vrele and DNUNLOCK
 * instead of two DNUNLOCKs.
 *
 * Overall outline of devfs_lookup:
 *
 *	check accessibility of directory
 *	null terminate the component (lookup leaves the whole string alone)
 *	look for name in cache, if found, then if at end of path
 *	  and deleting or creating, drop it, else return name
 *	search for name in directory, to found or notfound
 * notfound:
 *	if creating, return locked directory,
 *	else return error
 * found:
 *	if at end of path and deleting, return information to allow delete
 *	if at end of path and rewriting (RENAME and LOCKPARENT), lock target
 *	  node and return info to allow rewrite
 *	if not at end, add name to cache; if at end and neither creating
 *	  nor deleting, add name to cache
 * On return to lookup, remove the null termination we put in at the start.
 *
 * NOTE: (LOOKUP | LOCKPARENT) currently returns the parent node unlocked.
 */
static int
devfs_lookup(struct vop_lookup_args *ap)
        /*struct vop_lookup_args {
                struct vnode * a_dvp; directory vnode ptr
                struct vnode ** a_vpp; where to put the result
                struct componentname * a_cnp; the name we want
        };*/
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dir_vnode = ap->a_dvp;
	struct vnode **result_vnode = ap->a_vpp;
	devnode_t *   dir_node;       /* the directory we are searching */
	devnode_t *   node = NULL;       /* the node we are searching for */
	devdirent_t * nodename;
	int flags = cnp->cn_flags;
	int op = cnp->cn_nameiop;       /* LOOKUP, CREATE, RENAME, or DELETE */
	int lockparent = flags & LOCKPARENT;
	int wantparent = flags & (LOCKPARENT|WANTPARENT);
	int error = 0;
	struct proc *p = cnp->cn_proc;
	char	heldchar;	/* the char at the end of the name componet */

	*result_vnode = NULL; /* safe not sorry */ /*XXX*/

	if (dir_vnode->v_usecount == 0)
	    printf("devfs_lookup: dir had no refs ");
	dir_node = VTODN(dir_vnode);

	/*
	 * Check accessiblity of directory.
	 */
	if (dir_node->dn_type != DEV_DIR) {
		return (ENOTDIR);
	}

	if ((error = VOP_ACCESS(dir_vnode, VEXEC, cnp->cn_cred, p)) != 0) {
		return (error);
	}

	/* temporarily terminate string component */
	heldchar = cnp->cn_nameptr[cnp->cn_namelen];
	cnp->cn_nameptr[cnp->cn_namelen] = '\0';
	DEVFS_LOCK(p);
	nodename = dev_findname(dir_node,cnp->cn_nameptr);
	if (nodename) {
	    /* entry exists */
	    node = nodename->de_dnp;
	    node->dn_last_lookup = nodename; /* for unlink */
	    /* Do potential vnode allocation here inside the lock 
	     * to make sure that our device node has a non-NULL dn_vn
	     * associated with it.  The device node might otherwise
	     * get deleted out from under us (see devfs_dn_free()).
	     */
	    error = devfs_dntovn(node, result_vnode, p);
	}
	DEVFS_UNLOCK(p);
	/* restore saved character */
	cnp->cn_nameptr[cnp->cn_namelen] = heldchar;

	if (error)
	    return (error);

	if (!nodename) { /* no entry */
		/* If it doesn't exist and we're not the last component,
		 * or we're at the last component, but we're not creating
		 * or renaming, return ENOENT.
		 */
        	if (!(flags & ISLASTCN) || !(op == CREATE || op == RENAME)) {
			return ENOENT;
		}
		/*
		 * Access for write is interpreted as allowing
		 * creation of files in the directory.
		 */
		if ((error = VOP_ACCESS(dir_vnode, VWRITE,
				cnp->cn_cred, p)) != 0)
		{
			return (error);
		}
		/*
		 * We return with the directory locked, so that
		 * the parameters we set up above will still be
		 * valid if we actually decide to add a new entry.
		 * We return ni_vp == NULL to indicate that the entry
		 * does not currently exist; we leave a pointer to
		 * the (locked) directory vnode in namei_data->ni_dvp.
		 * The pathname buffer is saved so that the name
		 * can be obtained later.
		 *
		 * NB - if the directory is unlocked, then this
		 * information cannot be used.
		 */
		cnp->cn_flags |= SAVENAME;
		if (!lockparent)
			VOP_UNLOCK(dir_vnode, 0, p);
		return (EJUSTRETURN);
	}

	/*
	 * If deleting, and at end of pathname, return
	 * parameters which can be used to remove file.
	 * If the wantparent flag isn't set, we return only
	 * the directory (in namei_data->ni_dvp), otherwise we go
	 * on and lock the node, being careful with ".".
	 */
	if (op == DELETE && (flags & ISLASTCN)) {
		/*
		 * Write access to directory required to delete files.
		 */
		if ((error = VOP_ACCESS(dir_vnode, VWRITE,
				cnp->cn_cred, p)) != 0)
			return (error);
		/*
		 * we are trying to delete '.'.  What does this mean? XXX
		 */
		if (dir_node == node) {
			VREF(dir_vnode);
			*result_vnode = dir_vnode;
			return (0);
		}
#ifdef NOTYET
		/*
		 * If directory is "sticky", then user must own
		 * the directory, or the file in it, else she
		 * may not delete it (unless she's root). This
		 * implements append-only directories.
		 */
		if ((dir_node->mode & ISVTX) &&
		    cnp->cn_cred->cr_uid != 0 &&
		    cnp->cn_cred->cr_uid != dir_node->uid &&
		    cnp->cn_cred->cr_uid != node->uid) {
			VOP_UNLOCK(*result_vnode, 0, p);
			return (EPERM);
		}
#endif
		if (!lockparent)
			VOP_UNLOCK(dir_vnode, 0, p);
		return (0);
	}

	/*
	 * If rewriting (RENAME), return the vnode and the
	 * information required to rewrite the present directory
	 * Must get node of directory entry to verify it's a
	 * regular file, or empty directory.
	 */
	if (op == RENAME && wantparent && (flags & ISLASTCN)) {
		/*
		 * Are we allowed to change the holding directory?
		 */
		if ((error = VOP_ACCESS(dir_vnode, VWRITE,
				cnp->cn_cred, p)) != 0)
			return (error);
		/*
		 * Careful about locking second node.
		 * This can only occur if the target is ".".
		 */
		if (dir_node == node)
			return (EISDIR);
		/* hmm save the 'from' name (we need to delete it) */
		cnp->cn_flags |= SAVENAME;
		if (!lockparent)
			VOP_UNLOCK(dir_vnode, 0, p);
		return (0);
	}

	/*
	 * Step through the translation in the name.  We do not unlock the
	 * directory because we may need it again if a symbolic link
	 * is relative to the current directory.  Instead we save it
	 * unlocked as "saved_dir_node" XXX.  We must get the target
	 * node before unlocking
	 * the directory to insure that the node will not be removed
	 * before we get it.  We prevent deadlock by always fetching
	 * nodes from the root, moving down the directory tree. Thus
	 * when following backward pointers ".." we must unlock the
	 * parent directory before getting the requested directory.
	 * There is a potential race condition here if both the current
	 * and parent directories are removed before the lock for the
	 * node associated with ".." returns.  We hope that this occurs
	 * infrequently since we cannot avoid this race condition without
	 * implementing a sophisticated deadlock detection algorithm.
	 * Note also that this simple deadlock detection scheme will not
	 * work if the file system has any hard links other than ".."
	 * that point backwards in the directory structure.
	 */
	if (flags & ISDOTDOT) {
		VOP_UNLOCK(dir_vnode, 0, p);	/* race to get the node */
		if (lockparent && (flags & ISLASTCN))
			vn_lock(dir_vnode, LK_EXCLUSIVE | LK_RETRY, p);
	} else if (dir_node == node) {
#if 0
	    /* 
	     * this next statement is wrong: we already did a vget in 
	     * devfs_dntovn(); DWS 4/16/1999
	     */
	    	 VREF(dir_vnode);	 /* we want ourself, ie "." */
#endif
		*result_vnode = dir_vnode;
	} else {
		if (!lockparent || (flags & ISLASTCN))
			VOP_UNLOCK(dir_vnode, 0, p);
	}

	return (0);
}

static int
devfs_access(struct vop_access_args *ap)
        /*struct vop_access_args  {
                struct vnode *a_vp;
                int  a_mode;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ 
{
	/*
 	 *  mode is filled with a combination of VREAD, VWRITE,
 	 *  and/or VEXEC bits turned on.  In an octal number these
 	 *  are the Y in 0Y00.
 	 */
	struct vnode *vp = ap->a_vp;
	int mode = ap->a_mode;
	struct ucred *cred = ap->a_cred;
	devnode_t *	file_node;
	gid_t	*gp;
	int 	i;
	struct proc *p = ap->a_p;

	file_node = VTODN(vp);
	/* 
	 * if we are not running as a process, we are in the 
	 * kernel and we DO have permission
	 */
	if (p == NULL)
	    return 0;

	/*
	 * Access check is based on only one of owner, group, public.
	 * If not owner, then check group. If not a member of the
	 * group, then check public access.
	 */
	if (cred->cr_uid != file_node->dn_uid)
	{
		/* failing that.. try groups */
		mode >>= 3;
		gp = cred->cr_groups;
		for (i = 0; i < cred->cr_ngroups; i++, gp++)
		{
			if (file_node->dn_gid == *gp)
			{
				goto found;
			}
		}
		/* failing that.. try general access */
		mode >>= 3;
found:
		;
	}
	if ((file_node->dn_mode & mode) == mode)
		return (0);
	/*
	 *  Root gets to do anything.
	 * but only use suser prives as a last resort
	 * (Use of super powers is recorded in ap->a_p->p_acflag)
	 */
	if( suser(cred, &ap->a_p->p_acflag) == 0) /* XXX what if no proc? */
		return 0;
	return (EACCES);
}

static int
devfs_getattr(struct vop_getattr_args *ap)
        /*struct vop_getattr_args {
                struct vnode *a_vp;
                struct vattr *a_vap;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ 
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	devnode_t *	file_node;
	struct timeval  tv;

	file_node = VTODN(vp);
	tv = time;
	dn_times(file_node, tv, tv);
	vap->va_rdev = 0;/* default value only */
	vap->va_mode = file_node->dn_mode;
	switch (file_node->dn_type)
	{
	case 	DEV_DIR:
		vap->va_rdev = (dev_t)file_node->dn_dvm;
		vap->va_mode |= (S_IFDIR);
		break;
	case	DEV_CDEV:
		vap->va_rdev = file_node->dn_typeinfo.dev;
		vap->va_mode |= (S_IFCHR);
		break;
	case	DEV_BDEV:
		vap->va_rdev = file_node->dn_typeinfo.dev;
		vap->va_mode |= (S_IFBLK);
		break;
	case	DEV_SLNK:
		vap->va_mode |= (S_IFLNK);
		break;
	}
	vap->va_type = vp->v_type;
	vap->va_nlink = file_node->dn_links;
	vap->va_uid = file_node->dn_uid;
	vap->va_gid = file_node->dn_gid;
	vap->va_fsid = (int32_t)(void *)file_node->dn_dvm;
	vap->va_fileid = (int32_t)(void *)file_node;
	vap->va_size = file_node->dn_len; /* now a u_quad_t */
	/* this doesn't belong here */
	if (vp->v_type == VBLK)
		vap->va_blocksize = BLKDEV_IOSIZE;
	else if (vp->v_type == VCHR)
		vap->va_blocksize = MAXPHYSIO;
	else
		vap->va_blocksize = vp->v_mount->mnt_stat.f_iosize;
	/* if the time is bogus, set it to the boot time */
	if (file_node->dn_ctime.tv_sec == 0)
	    file_node->dn_ctime.tv_sec = boottime.tv_sec;
	if (file_node->dn_mtime.tv_sec == 0)
	    file_node->dn_mtime.tv_sec = boottime.tv_sec;
	if (file_node->dn_atime.tv_sec == 0)
	    file_node->dn_atime.tv_sec = boottime.tv_sec;
	vap->va_ctime = file_node->dn_ctime;
	vap->va_mtime = file_node->dn_mtime;
	vap->va_atime = file_node->dn_atime;
	vap->va_gen = 0;
	vap->va_flags = 0;
	vap->va_bytes = file_node->dn_len;		/* u_quad_t */
	vap->va_filerev = 0; /* XXX */		/* u_quad_t */
	vap->va_vaflags = 0; /* XXX */
	return 0;
}

static int
devfs_setattr(struct vop_setattr_args *ap)
        /*struct vop_setattr_args  {
                struct vnode *a_vp;
                struct vattr *a_vap;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ 
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct ucred *cred = ap->a_cred;
	struct proc *p = ap->a_p;
	int error = 0;
	gid_t *gp;
	int i;
	devnode_t *	file_node;
	struct timeval atimeval, mtimeval;

	if (vap->va_flags != VNOVAL)	/* XXX needs to be implemented */
		return (EOPNOTSUPP);

	file_node = VTODN(vp);

	if ((vap->va_type != VNON)  ||
	    (vap->va_nlink != VNOVAL)  ||
	    (vap->va_fsid != VNOVAL)  ||
	    (vap->va_fileid != VNOVAL)  ||
	    (vap->va_blocksize != VNOVAL)  ||
	    (vap->va_rdev != VNOVAL)  ||
	    (vap->va_bytes != VNOVAL)  ||
	    (vap->va_gen != VNOVAL ))
	{
		return EINVAL;
	}

	/*
	 * Go through the fields and update iff not VNOVAL.
	 */
	if (vap->va_atime.tv_sec != VNOVAL || vap->va_mtime.tv_sec != VNOVAL) {
	    if (cred->cr_uid != file_node->dn_uid &&
		(error = suser(cred, &p->p_acflag)) &&
		((vap->va_vaflags & VA_UTIMES_NULL) == 0 || 
		 (error = VOP_ACCESS(vp, VWRITE, cred, p))))
		return (error);
	    if (vap->va_atime.tv_sec != VNOVAL)
		file_node->dn_flags |= DN_ACCESS;
	    if (vap->va_mtime.tv_sec != VNOVAL)
		file_node->dn_flags |= DN_CHANGE | DN_UPDATE;
	    atimeval.tv_sec = vap->va_atime.tv_sec;
	    atimeval.tv_usec = vap->va_atime.tv_nsec / 1000;
	    mtimeval.tv_sec = vap->va_mtime.tv_sec;
	    mtimeval.tv_usec = vap->va_mtime.tv_nsec / 1000;
	    if (error = VOP_UPDATE(vp, &atimeval, &mtimeval, 1))
		return (error);
	}

	/*
	 * Change the permissions.. must be root or owner to do this.
	 */
	if (vap->va_mode != (u_short)VNOVAL) {
		if ((cred->cr_uid != file_node->dn_uid)
		 && (error = suser(cred, &p->p_acflag)))
			return (error);
		file_node->dn_mode &= ~07777;
		file_node->dn_mode |= vap->va_mode & 07777;
	}

	/*
	 * Change the owner.. must be root to do this.
	 */
	if (vap->va_uid != (uid_t)VNOVAL) {
		if (error = suser(cred, &p->p_acflag))
			return (error);
		file_node->dn_uid = vap->va_uid;
	}

	/*
	 * Change the group.. must be root or owner to do this.
	 * If we are the owner, we must be in the target group too.
	 * don't use suser() unless you have to as it reports
	 * whether you needed suser powers or not.
	 */
	if (vap->va_gid != (gid_t)VNOVAL) {
		if (cred->cr_uid == file_node->dn_uid){
			gp = cred->cr_groups;
			for (i = 0; i < cred->cr_ngroups; i++, gp++) {
				if (vap->va_gid == *gp)
					goto cando; 
			}
		}
		/*
		 * we can't do it with normal privs,
		 * do we have an ace up our sleeve?
		 */
	 	if (error = suser(cred, &p->p_acflag))
			return (error);
cando:
		file_node->dn_gid = vap->va_gid;
	}
#if 0
	/*
 	 * Copied from somewhere else
	 * but only kept as a marker and reminder of the fact that
	 * flags should be handled some day
	 */
	if (vap->va_flags != VNOVAL) {
		if (error = suser(cred, &p->p_acflag))
			return error;
		if (cred->cr_uid == 0)
		;
		else {
		}
	}
#endif
	return error;
}

static int
devfs_read(struct vop_read_args *ap)
        /*struct vop_read_args {
                struct vnode *a_vp;
                struct uio *a_uio;
                int  a_ioflag;
                struct ucred *a_cred;
        } */
{
    	devnode_t * dn_p = VTODN(ap->a_vp);

	switch (ap->a_vp->v_type) {
	  case VDIR: {
	      dn_p->dn_flags |= DN_ACCESS;
	      return VOP_READDIR(ap->a_vp, ap->a_uio, ap->a_cred,
				 NULL, NULL, NULL);
	  }
	  default: {
	      printf("devfs_read(): bad file type %d", ap->a_vp->v_type);
	      return(EINVAL);
	      break;
	  }
	}
	return (0); /* not reached */
}

static int
devfs_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
    	struct vnode *	    	vp = ap->a_vp;
	register devnode_t * 	dnp = VTODN(vp);

	simple_lock(&vp->v_interlock);
	if (vp->v_usecount > 1)
	    dn_times(dnp, time, time);
	simple_unlock(&vp->v_interlock);
	return (0);
}

static int
devfsspec_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
    	struct vnode *	    	vp = ap->a_vp;
	register devnode_t * 	dnp = VTODN(vp);

	simple_lock(&vp->v_interlock);
	if (vp->v_usecount > 1)
	    dn_times(dnp, time, time);
	simple_unlock(&vp->v_interlock);
	return (VOCALL (spec_vnodeop_p, VOFFSET(vop_close), ap));
}

static int
devfsspec_read(struct vop_read_args *ap)
        /*struct vop_read_args {
                struct vnode *a_vp;
                struct uio *a_uio;
                int  a_ioflag;
                struct ucred *a_cred;
        } */
{
    VTODN(ap->a_vp)->dn_flags |= DN_ACCESS;
    return (VOCALL (spec_vnodeop_p, VOFFSET(vop_read), ap));
}

static int
devfsspec_write(struct vop_write_args *ap)
        /*struct vop_write_args  {
                struct vnode *a_vp;
                struct uio *a_uio;
                int  a_ioflag;
                struct ucred *a_cred;
        } */
{
    VTODN(ap->a_vp)->dn_flags |= DN_CHANGE | DN_UPDATE;
    return (VOCALL (spec_vnodeop_p, VOFFSET(vop_write), ap));
}

/*
 *  Write data to a file or directory.
 */
static int
devfs_write(struct vop_write_args *ap)
        /*struct vop_write_args  {
                struct vnode *a_vp;
                struct uio *a_uio;
                int  a_ioflag;
                struct ucred *a_cred;
        } */
{
	switch (ap->a_vp->v_type) {
	case VDIR:
		return(EISDIR);
	default:
		printf("devfs_write(): bad file type %d", ap->a_vp->v_type);
		return (EINVAL);
	}
	return 0; /* not reached */
}

static int
devfs_remove(struct vop_remove_args *ap)
        /*struct vop_remove_args  {
                struct vnode *a_dvp;
                struct vnode *a_vp;
                struct componentname *a_cnp;
        } */ 
{
	struct vnode *vp = ap->a_vp;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	devnode_t *  tp;
	devnode_t *  tdp;
	devdirent_t * tnp;
	int doingdirectory = 0;
	int error = 0;
	uid_t ouruid = cnp->cn_cred->cr_uid;
	struct proc *p = cnp->cn_proc;

	/*
	 * Lock our directories and get our name pointers
	 * assume that the names are null terminated as they
	 * are the end of the path. Get pointers to all our
	 * devfs structures.
	 */
	tp = VTODN(vp);
	tdp = VTODN(dvp);
	/*
	 * Assuming we are atomic, dev_lookup left this for us
	 */
	tnp = tp->dn_last_lookup;

	/*
	 * Check we are doing legal things WRT the new flags
	 */
	if ((tp->dn_flags & (IMMUTABLE | APPEND))
	  || (tdp->dn_flags & APPEND) /*XXX eh?*/ ) {
	    error = EPERM;
	    goto abort;
	}

	/*
	 * Make sure that we don't try do something stupid
	 */
	if ((tp->dn_type) == DEV_DIR) {
		/*
		 * Avoid ".", "..", and aliases of "." for obvious reasons.
		 */
		if ( (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') 
		    || (cnp->cn_flags&ISDOTDOT) ) {
			error = EINVAL;
			goto abort;
		}
		doingdirectory++;
	}

	/***********************************
	 * Start actually doing things.... *
	 ***********************************/
	tdp->dn_flags |= DN_CHANGE | DN_UPDATE;

	/*
	 * own the parent directory, or the destination of the rename,
	 * otherwise the destination may not be changed (except by
	 * root). This implements append-only directories.
	 * XXX shoudn't this be in generic code? 
	 */
	if ((tdp->dn_mode & S_ISTXT)
	  && ouruid != 0
	  && ouruid != tdp->dn_uid
	  && ouruid != tp->dn_uid ) {
	    error = EPERM;
	    goto abort;
	}
	/*
	 * Target must be empty if a directory and have no links
	 * to it. Also, ensure source and target are compatible
	 * (both directories, or both not directories).
	 */
	if (( doingdirectory) && (tp->dn_links > 2)) {
	    error = ENOTEMPTY;
	    goto abort;
	}
	DEVFS_LOCK(p);
	dev_free_name(tnp);
	DEVFS_UNLOCK(p);
 abort:
	if (dvp == vp)
	    vrele(vp);
	else
	    vput(vp);
	vput(dvp);
	return (error);
}

/*
 */
static int
devfs_link(struct vop_link_args *ap)
        /*struct vop_link_args  {
                struct vnode *a_tdvp;
                struct vnode *a_vp;
                struct componentname *a_cnp;
        } */ 
{
	struct vnode *vp = ap->a_vp;
	struct vnode *tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;
	struct proc *p = cnp->cn_proc;
	devnode_t * fp;
	devnode_t * tdp;
	devdirent_t * tnp;
	int error = 0;
	struct timeval tv;

	/*
	 * First catch an arbitrary restriction for this FS
	 */
	if (cnp->cn_namelen > DEVMAXNAMESIZE) {
		error = ENAMETOOLONG;
		goto out1;
	}

	/*
	 * Lock our directories and get our name pointers
	 * assume that the names are null terminated as they
	 * are the end of the path. Get pointers to all our
	 * devfs structures.
	 */
	tdp = VTODN(tdvp);
	fp = VTODN(vp);
	
	if (tdvp->v_mount != vp->v_mount) {
		error = EXDEV;
		VOP_ABORTOP(tdvp, cnp); 
		goto out2;
	}
	if (tdvp != vp && (error = vn_lock(vp, LK_EXCLUSIVE, p))) {
		VOP_ABORTOP(tdvp, cnp);
		goto out2;
	}

	/*
	 * Check we are doing legal things WRT the new flags
	 */
	if (fp->dn_flags & (IMMUTABLE | APPEND)) {
		VOP_ABORTOP(tdvp, cnp);
		error = EPERM;
		goto out1;
	}

	/***********************************
	 * Start actually doing things.... *
	 ***********************************/
	fp->dn_flags |= DN_CHANGE;
	tv = time;
	error = VOP_UPDATE(vp, &tv, &tv, 1);
	if (!error) {
	    DEVFS_LOCK(p);
	    error = dev_add_name(cnp->cn_nameptr, tdp, NULL, fp, &tnp);
	    DEVFS_UNLOCK(p);
	}
out1:
	if (tdvp != vp)
		VOP_UNLOCK(vp, 0, p);
out2:
	vput(tdvp);
	return (error);
}

/*
 * Check if source directory is in the path of the target directory.
 * Target is supplied locked, source is unlocked.
 * The target is always vput before returning.
 */
int
devfs_checkpath(source, target)
	devnode_t *source, *target;
{
    int error = 0;
    devnode_t * ntmp;
    devnode_t * tmp;
    struct vnode *vp;

    vp = target->dn_vn;
    tmp = target;

    do {
	if (tmp == source) {
	    error = EINVAL;
	    break;
	}
	ntmp = tmp;
    } while ((tmp = tmp->dn_typeinfo.Dir.parent) != ntmp);

    if (vp != NULL)
	vput(vp);
    return (error);
}

/*
 * Rename system call. Seems overly complicated to me...
 * 	rename("foo", "bar");
 * is essentially
 *	unlink("bar");
 *	link("foo", "bar");
 *	unlink("foo");
 * but ``atomically''.
 *
 * When the target exists, both the directory
 * and target vnodes are locked.
 * the source and source-parent vnodes are referenced
 *
 *
 * Basic algorithm is:
 *
 * 1) Bump link count on source while we're linking it to the
 *    target.  This also ensure the inode won't be deleted out
 *    from underneath us while we work (it may be truncated by
 *    a concurrent `trunc' or `open' for creation).
 * 2) Link source to destination.  If destination already exists,
 *    delete it first.
 * 3) Unlink source reference to node if still around. If a
 *    directory was moved and the parent of the destination
 *    is different from the source, patch the ".." entry in the
 *    directory.
 */
static int
devfs_rename(struct vop_rename_args *ap)
        /*struct vop_rename_args  {
                struct vnode *a_fdvp; 
                struct vnode *a_fvp;  
                struct componentname *a_fcnp;
                struct vnode *a_tdvp;
                struct vnode *a_tvp;
                struct componentname *a_tcnp;
        } */
{
	struct vnode *tvp = ap->a_tvp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *fdvp = ap->a_fdvp;
	struct componentname *tcnp = ap->a_tcnp;
	struct componentname *fcnp = ap->a_fcnp;
	struct proc *p = fcnp->cn_proc;
	devnode_t *fp, *fdp, *tp, *tdp;
	devdirent_t *fnp,*tnp;
	int doingdirectory = 0;
	int error = 0;
	struct timeval tv;

	/*
	 * First catch an arbitrary restriction for this FS
	 */
	if(tcnp->cn_namelen > DEVMAXNAMESIZE) {
		error = ENAMETOOLONG;
		goto abortit;
	}

	/*
	 * Lock our directories and get our name pointers
	 * assume that the names are null terminated as they
	 * are the end of the path. Get pointers to all our
	 * devfs structures.
	 */
	tdp = VTODN(tdvp);
	fdp = VTODN(fdvp);
	fp = VTODN(fvp);
	fnp = fp->dn_last_lookup;
	tp = NULL;
	tnp = NULL;
	if (tvp) {
	    tp = VTODN(tvp);
	    tnp = tp->dn_last_lookup;
	}
	
	/*
	 * trying to move it out of devfs?
         * if we move a dir across mnt points. we need to fix all
	 * the mountpoint pointers! XXX
	 * so for now keep dirs within the same mount
	 */
	if ((fvp->v_mount != tdvp->v_mount) ||
	    (tvp && (fvp->v_mount != tvp->v_mount))) {
		error = EXDEV;
abortit:
		VOP_ABORTOP(tdvp, tcnp); 
		if (tdvp == tvp) /* eh? */
			vrele(tdvp);
		else
			vput(tdvp);
		if (tvp)
			vput(tvp);
		VOP_ABORTOP(fdvp, fcnp); /* XXX, why not in NFS? */
		vrele(fdvp);
		vrele(fvp);
		return (error);
	}

	/*
	 * Check we are doing legal things WRT the new flags
	 */
	if ((tp && (tp->dn_flags & (IMMUTABLE | APPEND)))
	  || (fp->dn_flags & (IMMUTABLE | APPEND))
	  || (fdp->dn_flags & APPEND)) {
		error = EPERM;
		goto abortit;
	}

	/*
	 * Make sure that we don't try do something stupid
	 */
	if ((fp->dn_type) == DEV_DIR) {
		/*
		 * Avoid ".", "..", and aliases of "." for obvious reasons.
		 */
		if ((fcnp->cn_namelen == 1 && fcnp->cn_nameptr[0] == '.') 
		    || (fcnp->cn_flags&ISDOTDOT) 
		    || (tcnp->cn_namelen == 1 && tcnp->cn_nameptr[0] == '.') 
		    || (tcnp->cn_flags&ISDOTDOT) 
		    || (tdp == fp )) {
			error = EINVAL;
			goto abortit;
		}
		doingdirectory++;
	}

	/*
	 * If ".." must be changed (ie the directory gets a new
	 * parent) then the source directory must not be in the
	 * directory hierarchy above the target, as this would
	 * orphan everything below the source directory. Also
	 * the user must have write permission in the source so
	 * as to be able to change "..". 
	 */
	if (doingdirectory && (tdp != fdp)) {
		devnode_t * tmp, *ntmp;
		error = VOP_ACCESS(fvp, VWRITE, tcnp->cn_cred, tcnp->cn_proc);
		tmp = tdp;
		do {
			if(tmp == fp) {
				/* XXX unlock stuff here probably */
				error = EINVAL;
				goto out;
			}
			ntmp = tmp;
		} while ((tmp = tmp->dn_typeinfo.Dir.parent) != ntmp);
	}

	/***********************************
	 * Start actually doing things.... *
	 ***********************************/
	fp->dn_flags |= DN_CHANGE;
	tv = time;
	if (error = VOP_UPDATE(fvp, &tv, &tv, 1)) {
	    VOP_UNLOCK(fvp, 0, p);
	    goto bad;
	}
	/*
	 * Check if just deleting a link name.
	 */
	if (fvp == tvp) {
		if (fvp->v_type == VDIR) {
			error = EINVAL;
			goto abortit;
		}

		/* Release destination completely. */
		VOP_ABORTOP(tdvp, tcnp);
		vput(tdvp);
		vput(tvp);

		/* Delete source. */
		VOP_ABORTOP(fdvp, fcnp); /*XXX*/
		vrele(fdvp);
		vrele(fvp);
		dev_free_name(fnp);
		return 0;
	}

	vrele(fdvp);

	/*
	 * 1) Bump link count while we're moving stuff
	 *    around.  If we crash somewhere before
	 *    completing our work,  too bad :)
	 */
	fp->dn_links++;
	/*
	 * If the target exists zap it (unless it's a non-empty directory)
	 * We could do that as well but won't
 	 */
	if (tp) {
		int ouruid = tcnp->cn_cred->cr_uid;
		/*
		 * If the parent directory is "sticky", then the user must
		 * own the parent directory, or the destination of the rename,
		 * otherwise the destination may not be changed (except by
		 * root). This implements append-only directories.
		 * XXX shoudn't this be in generic code? 
		 */
		if ((tdp->dn_mode & S_ISTXT)
		  && ouruid != 0
		  && ouruid != tdp->dn_uid
		  && ouruid != tp->dn_uid ) {
			error = EPERM;
			goto bad;
		}
		/*
		 * Target must be empty if a directory and have no links
		 * to it. Also, ensure source and target are compatible
		 * (both directories, or both not directories).
		 */
		if (( doingdirectory) && (tp->dn_links > 2)) {
				error = ENOTEMPTY;
				goto bad;
		}
		dev_free_name(tnp);
		tp = NULL;
	}
	dev_add_name(tcnp->cn_nameptr,tdp,NULL,fp,&tnp);
	fnp->de_dnp = NULL;
	fp->dn_links--; /* one less link to it.. */
	dev_free_name(fnp);
	fp->dn_links--; /* we added one earlier*/
	if (tdp)
		vput(tdvp);
	if (tp)
		vput(fvp);
	vrele(fvp);
	return (error);

bad:
	if (tp)
		vput(tvp);
	vput(tdvp);
out:
	if (vn_lock(fvp, LK_EXCLUSIVE | LK_RETRY, p) == 0) {
		fp->dn_links--; /* we added one earlier*/
		vput(fvp);
	} else
		vrele(fvp);
	return (error);
}

static int
devfs_symlink(struct vop_symlink_args *ap)
        /*struct vop_symlink_args {
                struct vnode *a_dvp;
                struct vnode **a_vpp;
                struct componentname *a_cnp;
                struct vattr *a_vap;
                char *a_target;
        } */
{
	struct componentname * cnp = ap->a_cnp;
	struct vnode *vp = NULL;
	int error = 0;
	devnode_t * dir_p;
	devnode_type_t typeinfo;
	devdirent_t * nm_p;
	devnode_t * dev_p;
	struct vattr *	vap = ap->a_vap;
	struct vnode * * vpp = ap->a_vpp;
	struct proc *p = cnp->cn_proc;
	struct timeval tv;

	dir_p = VTODN(ap->a_dvp);
	typeinfo.Slnk.name = ap->a_target;
	typeinfo.Slnk.namelen = strlen(ap->a_target);
	DEVFS_LOCK(p);
	error = dev_add_entry(cnp->cn_nameptr, dir_p, DEV_SLNK, 
			      &typeinfo, NULL, NULL, &nm_p);
	DEVFS_UNLOCK(p);
	if (error) {
	    goto failure;
	}
	
	dev_p = nm_p->de_dnp;
	dev_p->dn_uid = dir_p->dn_uid;
	dev_p->dn_gid = dir_p->dn_gid;
	dev_p->dn_mode = vap->va_mode;
	dn_copy_times(dev_p, dir_p);
	error = devfs_dntovn(dev_p, vpp, p);
	if (error)
	    goto failure;
	vp = *vpp;
	vput(vp);
failure:
	if ((cnp->cn_flags & SAVESTART) == 0) {
		char *tmp = cnp->cn_pnbuf;
		cnp->cn_pnbuf = NULL;
		cnp->cn_flags &= ~HASBUF;
	    FREE_ZONE(tmp, cnp->cn_pnlen, M_NAMEI);
	}
	vput(ap->a_dvp);
	return error;
}

/*
 * Mknod vnode call
 */
/* ARGSUSED */
int
devfs_mknod(ap)
	struct vop_mknod_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
    	struct componentname * cnp = ap->a_cnp;
	devnode_t *	dev_p;
	devdirent_t *	devent;
	devnode_t *	dir_p;	/* devnode for parent directory */
    	struct vnode * 	dvp = ap->a_dvp;
	int 		error = 0;
	devnode_type_t	typeinfo;
	struct vattr *	vap = ap->a_vap;
	struct vnode ** vpp = ap->a_vpp;
	struct proc *	p = cnp->cn_proc;

	*vpp = NULL;
	if (!vap->va_type == VBLK && !vap->va_type == VCHR) {
	    error = EINVAL; /* only support mknod of special files */
	    goto failure;
	}
	dir_p = VTODN(dvp);
	typeinfo.dev = vap->va_rdev;
	DEVFS_LOCK(p);
	error = dev_add_entry(cnp->cn_nameptr, dir_p, 
			      (vap->va_type == VBLK) ? DEV_BDEV : DEV_CDEV,
			      &typeinfo, NULL, NULL, &devent);
	DEVFS_UNLOCK(p);
	if (error) {
	    goto failure;
	}
	dev_p = devent->de_dnp;
	error = devfs_dntovn(dev_p, vpp, p);
	if (error)
	    goto failure;
	dev_p->dn_uid = cnp->cn_cred->cr_uid;
	dev_p->dn_gid = dir_p->dn_gid;
	dev_p->dn_mode = vap->va_mode;
failure:
	if (*vpp) {
	    vput(*vpp);
	    *vpp = 0;
	}
	if ((cnp->cn_flags & SAVESTART) == 0) {
		char *tmp = cnp->cn_pnbuf;
		cnp->cn_pnbuf = NULL;
		cnp->cn_flags &= ~HASBUF;
	    FREE_ZONE(tmp, cnp->cn_pnlen, M_NAMEI);
	}
	vput(dvp);
	return (error);
}

/*
 * Vnode op for readdir
 */
static int
devfs_readdir(struct vop_readdir_args *ap)
        /*struct vop_readdir_args {
                struct vnode *a_vp;
                struct uio *a_uio;
                struct ucred *a_cred;
        	int *eofflag;
        	int *ncookies;
        	u_int **cookies;
        } */
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct dirent dirent;
	devnode_t * dir_node;
	devdirent_t *	name_node;
	char	*name;
	int error = 0;
	int reclen;
	int nodenumber;
	int	startpos,pos;
	struct proc *	p = uio->uio_procp;

	/*  set up refs to dir */
	dir_node = VTODN(vp);
	if(dir_node->dn_type != DEV_DIR)
		return(ENOTDIR);

	pos = 0;
	startpos = uio->uio_offset;
	DEVFS_LOCK(p);
	name_node = dir_node->dn_typeinfo.Dir.dirlist;
	nodenumber = 0;
	dir_node->dn_flags |= DN_ACCESS;

	while ((name_node || (nodenumber < 2)) && (uio->uio_resid > 0))
	{
		switch(nodenumber)
		{
		case	0:
			dirent.d_fileno = (int32_t)(void *)dir_node;
			name = ".";
			dirent.d_namlen = 1;
			dirent.d_type = DT_DIR;
			break;
		case	1:
			if(dir_node->dn_typeinfo.Dir.parent)
			    dirent.d_fileno
				= (int32_t)dir_node->dn_typeinfo.Dir.parent;
			else
				dirent.d_fileno = (u_int32_t)dir_node;
			name = "..";
			dirent.d_namlen = 2;
			dirent.d_type = DT_DIR;
			break;
		default:
			dirent.d_fileno = (int32_t)(void *)name_node->de_dnp;
			dirent.d_namlen = strlen(name_node->de_name);
			name = name_node->de_name;
			switch(name_node->de_dnp->dn_type) {
			case DEV_BDEV:
				dirent.d_type = DT_BLK;
				break;
			case DEV_CDEV:
				dirent.d_type = DT_CHR;
				break;
			case DEV_DIR:
				dirent.d_type = DT_DIR;
				break;
			case DEV_SLNK:
				dirent.d_type = DT_LNK;
				break;
			default:
				dirent.d_type = DT_UNKNOWN;
			}
		}
#define	GENERIC_DIRSIZ(dp) \
    ((sizeof (struct dirent) - (MAXNAMLEN+1)) + (((dp)->d_namlen+1 + 3) &~ 3))

		reclen = dirent.d_reclen = GENERIC_DIRSIZ(&dirent);

		if(pos >= startpos)	/* made it to the offset yet? */
		{
			if (uio->uio_resid < reclen) /* will it fit? */
				break;
			strcpy( dirent.d_name,name);
			if ((error = uiomove ((caddr_t)&dirent,
					dirent.d_reclen, uio)) != 0)
				break;
		}
		pos += reclen;
		if((nodenumber >1) && name_node)
			name_node = name_node->de_next;
		nodenumber++;
	}
	DEVFS_UNLOCK(p);
	uio->uio_offset = pos;

	return (error);
}


/*
 */
static int
devfs_readlink(struct vop_readlink_args *ap)
        /*struct vop_readlink_args {
                struct vnode *a_vp;
                struct uio *a_uio;
                struct ucred *a_cred;
        } */
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	devnode_t * lnk_node;
	int error = 0;

	/*  set up refs to dir */
	lnk_node = VTODN(vp);
	if(lnk_node->dn_type != DEV_SLNK)
		return(EINVAL);
	if ((error = VOP_ACCESS(vp, VREAD, ap->a_cred, NULL)) != 0) { /* XXX */
		return error;
	}
	error = uiomove(lnk_node->dn_typeinfo.Slnk.name, 
			lnk_node->dn_typeinfo.Slnk.namelen, uio);
	return error;
}

static int
devfs_reclaim(struct vop_reclaim_args *ap)
        /*struct vop_reclaim_args {
		struct vnode *a_vp;
        } */
{
    struct vnode *	vp = ap->a_vp;
    devnode_t * 	dnp = VTODN(vp);
    
    if (dnp) {
	/* 
	 * do the same as devfs_inactive in case it is not called
	 * before us (can that ever happen?)
	 */
	dnp->dn_vn = NULL;
	vp->v_data = NULL;
	if (dnp->dn_delete) {
	    devnode_free(dnp);
	}
    }
    return(0);
}

/*
 * Print out the contents of a /devfs vnode.
 */
static int
devfs_print(struct vop_print_args *ap)
	/*struct vop_print_args {
		struct vnode *a_vp;
	} */
{

	return (0);
}

/**************************************************************************\
* pseudo ops *
\**************************************************************************/

/*
 *
 *	struct vop_inactive_args {
 *		struct vnode *a_vp;
 *		struct proc *a_p;
 *	} 
 */

static int
devfs_inactive(struct vop_inactive_args *ap)
{
    struct vnode *	vp = ap->a_vp;
    devnode_t * 	dnp = VTODN(vp);
    
    if (dnp) {
	dnp->dn_vn = NULL;
	vp->v_data = NULL;
	if (dnp->dn_delete) {
	    devnode_free(dnp);
	}
    }
    VOP_UNLOCK(vp, 0, ap->a_p);
    return (0);
}

int
devfs_update(ap)
	struct vop_update_args /* {
		struct vnode *a_vp;
		struct timeval *a_access;
		struct timeval *a_modify;
		int a_waitfor;
	} */ *ap;
{
	register struct fs *fs;
	int error;
	devnode_t * ip;

	ip = VTODN(ap->a_vp);
	if (ap->a_vp->v_mount->mnt_flag & MNT_RDONLY) {
		ip->dn_flags &=
		    ~(DN_ACCESS | DN_CHANGE | DN_MODIFIED | DN_UPDATE);
		return (0);
	}
	if ((ip->dn_flags &
	    (DN_ACCESS | DN_CHANGE | DN_MODIFIED | DN_UPDATE)) == 0)
		return (0);
	dn_times(ip, time, time);
	return (0);
}

#define VOPFUNC int (*)(void *)

/* The following ops are used by directories and symlinks */
int (**devfs_vnodeop_p)(void *);
static struct vnodeopv_entry_desc devfs_vnodeop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)devfs_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)err_create },		/* create */
	{ &vop_whiteout_desc, (VOPFUNC)err_whiteout },		/* whiteout */
	{ &vop_mknod_desc, (VOPFUNC)devfs_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)nop_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)devfs_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)devfs_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)devfs_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)devfs_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)devfs_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)devfs_write },		/* write */
	{ &vop_lease_desc, (VOPFUNC)nop_lease },		/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)err_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)err_select },		/* select */
	{ &vop_revoke_desc, (VOPFUNC)err_revoke },		/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)err_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)nop_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)err_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)devfs_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)devfs_link },		/* link */
	{ &vop_rename_desc, (VOPFUNC)devfs_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)err_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)err_rmdir },		/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)devfs_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)devfs_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)devfs_readlink },	/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)nop_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)devfs_inactive },	/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)devfs_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)nop_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)nop_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)err_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)err_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)err_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)nop_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)err_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)err_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)err_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)err_valloc },		/* valloc */
	{ &vop_reallocblks_desc, (VOPFUNC)err_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (VOPFUNC)err_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)err_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)devfs_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)err_bwrite },
	{ &vop_pagein_desc, (VOPFUNC)err_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)err_pageout },		/* Pageout */
	{ &vop_copyfile_desc, (VOPFUNC)err_copyfile },		/* Copyfile */
	{ &vop_blktooff_desc, (VOPFUNC)err_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)err_offtoblk },		/* offtoblk */
	{ &vop_cmap_desc, (VOPFUNC)err_cmap },		/* cmap */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc devfs_vnodeop_opv_desc =
	{ &devfs_vnodeop_p, devfs_vnodeop_entries };

/* The following ops are used by the device nodes */
int (**devfs_spec_vnodeop_p)(void *);
static struct vnodeopv_entry_desc devfs_spec_vnodeop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)spec_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)spec_create },		/* create */
	{ &vop_mknod_desc, (VOPFUNC)spec_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)spec_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)devfsspec_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)devfs_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)devfs_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)devfs_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)devfsspec_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)devfsspec_write },		/* write */
	{ &vop_lease_desc, (VOPFUNC)spec_lease_check },		/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)spec_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)spec_select },		/* select */
	{ &vop_revoke_desc, (VOPFUNC)spec_revoke },		/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)spec_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)spec_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)spec_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)devfs_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)devfs_link },		/* link */
	{ &vop_rename_desc, (VOPFUNC)spec_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)spec_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)spec_rmdir },		/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)spec_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)spec_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)spec_readlink },		/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)spec_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)devfs_inactive },	/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)devfs_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)nop_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)nop_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)spec_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)spec_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)devfs_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)nop_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)spec_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)spec_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)spec_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)spec_valloc },		/* valloc */
	{ &vop_reallocblks_desc, (VOPFUNC)spec_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (VOPFUNC)nop_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)spec_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)devfs_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vop_devblocksize_desc, (VOPFUNC)spec_devblocksize },	/* devblocksize */
	{ &vop_pagein_desc, (VOPFUNC)err_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)err_pageout },		/* Pageout */
	{ &vop_copyfile_desc, (VOPFUNC)err_copyfile },		/* Copyfile */
	{ &vop_blktooff_desc, (VOPFUNC)spec_blktooff },	/* blktooff */
	{ &vop_blktooff_desc, (VOPFUNC)spec_offtoblk  },	/* blkofftoblk */
	{ &vop_cmap_desc, (VOPFUNC)spec_cmap },	/* cmap */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc devfs_spec_vnodeop_opv_desc =
	{ &devfs_spec_vnodeop_p, devfs_spec_vnodeop_entries };

