/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/disklabel.h>
#include <sys/lock.h>
#include <sys/stat.h>
#include <sys/mount_internal.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/time.h>
#include <sys/vnode_internal.h>
#include <miscfs/specfs/specdev.h>
#include <sys/dirent.h>
#include <sys/vmmeter.h>
#include <sys/vm.h>
#include <sys/uio_internal.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include "devfsdefs.h"
#include "devfs.h"

#if FDESC
#include "fdesc.h"
#endif /* FDESC */

static int              devfs_update(struct vnode *vp, struct timeval *access,
    struct timeval *modify);
void                    devfs_rele_node(devnode_t *);
static void             devfs_consider_time_update(devnode_t *dnp, uint32_t just_changed_flags);
static boolean_t        devfs_update_needed(long now_s, long last_s);
static boolean_t        devfs_is_name_protected(struct vnode *dvp, const char *name);
void                    dn_times_locked(devnode_t * dnp, struct timeval *t1, struct timeval *t2, struct timeval *t3, uint32_t just_changed_flags);
void                    dn_times_now(devnode_t *dnp, uint32_t just_changed_flags);
void                    dn_mark_for_delayed_times_update(devnode_t *dnp, uint32_t just_changed_flags);

void
dn_times_locked(devnode_t * dnp, struct timeval *t1, struct timeval *t2, struct timeval *t3, uint32_t just_changed_flags)
{
	lck_mtx_assert(&devfs_attr_mutex, LCK_MTX_ASSERT_OWNED);

	if (just_changed_flags & DEVFS_UPDATE_ACCESS) {
		dnp->dn_atime.tv_sec = t1->tv_sec;
		dnp->dn_atime.tv_nsec = t1->tv_usec * 1000;
		dnp->dn_access = 0;
	} else if (dnp->dn_access) {
		dnp->dn_atime.tv_sec = MIN(t1->tv_sec, dnp->dn_atime.tv_sec + DEVFS_LAZY_UPDATE_SECONDS);
		dnp->dn_atime.tv_nsec = t1->tv_usec * 1000;
		dnp->dn_access = 0;
	}

	if (just_changed_flags & DEVFS_UPDATE_MOD) {
		dnp->dn_mtime.tv_sec = t2->tv_sec;
		dnp->dn_mtime.tv_nsec = t2->tv_usec * 1000;
		dnp->dn_update = 0;
	} else if (dnp->dn_update) {
		dnp->dn_mtime.tv_sec = MIN(t2->tv_sec, dnp->dn_mtime.tv_sec + DEVFS_LAZY_UPDATE_SECONDS);
		dnp->dn_mtime.tv_nsec = t2->tv_usec * 1000;
		dnp->dn_update = 0;
	}

	if (just_changed_flags & DEVFS_UPDATE_CHANGE) {
		dnp->dn_ctime.tv_sec = t3->tv_sec;
		dnp->dn_ctime.tv_nsec = t3->tv_usec * 1000;
		dnp->dn_change = 0;
	} else if (dnp->dn_change) {
		dnp->dn_ctime.tv_sec = MIN(t3->tv_sec, dnp->dn_ctime.tv_sec + DEVFS_LAZY_UPDATE_SECONDS);
		dnp->dn_ctime.tv_nsec = t3->tv_usec * 1000;
		dnp->dn_change = 0;
	}
}

void
dn_mark_for_delayed_times_update(devnode_t *dnp, uint32_t just_changed_flags)
{
	if (just_changed_flags & DEVFS_UPDATE_CHANGE) {
		dnp->dn_change = 1;
	}
	if (just_changed_flags & DEVFS_UPDATE_ACCESS) {
		dnp->dn_access = 1;
	}
	if (just_changed_flags & DEVFS_UPDATE_MOD) {
		dnp->dn_update = 1;
	}
}

/*
 * Update times based on pending updates and optionally a set of new changes.
 */
void
dn_times_now(devnode_t * dnp, uint32_t just_changed_flags)
{
	struct timeval now;

	DEVFS_ATTR_LOCK_SPIN();
	microtime(&now);
	dn_times_locked(dnp, &now, &now, &now, just_changed_flags);
	DEVFS_ATTR_UNLOCK();
}

/*
 * Critical devfs devices cannot be renamed or removed.
 * However, links to them may be moved/unlinked. So we block
 * remove/rename on a per-name basis, rather than per-node.
 */
static boolean_t
devfs_is_name_protected(struct vnode *dvp, const char *name)
{
	/*
	 * Only names in root are protected. E.g. /dev/null is protected,
	 * but /dev/foo/null isn't.
	 */
	if (!vnode_isvroot(dvp)) {
		return FALSE;
	}

	if ((strcmp("console", name) == 0) ||
	    (strcmp("tty", name) == 0) ||
	    (strcmp("null", name) == 0) ||
	    (strcmp("zero", name) == 0) ||
	    (strcmp("klog", name) == 0)) {
		return TRUE;
	}

	return FALSE;
}


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
devfs_lookup(struct vnop_lookup_args *ap)
/*struct vnop_lookup_args {
 *       struct vnode * a_dvp; directory vnode ptr
 *       struct vnode ** a_vpp; where to put the result
 *       struct componentname * a_cnp; the name we want
 *       vfs_context_t a_context;
 *  };*/
{
	struct componentname *cnp = ap->a_cnp;
	vfs_context_t ctx = cnp->cn_context;
	struct proc *p = vfs_context_proc(ctx);
	struct vnode *dir_vnode = ap->a_dvp;
	struct vnode **result_vnode = ap->a_vpp;
	devnode_t *   dir_node;       /* the directory we are searching */
	devnode_t *   node = NULL;       /* the node we are searching for */
	devdirent_t * nodename;
	int flags = cnp->cn_flags;
	int op = cnp->cn_nameiop;       /* LOOKUP, CREATE, RENAME, or DELETE */
	int wantparent = flags & (LOCKPARENT | WANTPARENT);
	int error = 0;
	char    heldchar;       /* the char at the end of the name componet */

retry:

	*result_vnode = NULL; /* safe not sorry */ /*XXX*/

	/*  okay to look at directory vnodes ourside devfs lock as they are not aliased */
	dir_node = VTODN(dir_vnode);

	/*
	 * Make sure that our node is a directory as well.
	 */
	if (dir_node->dn_type != DEV_DIR) {
		return ENOTDIR;
	}

	DEVFS_LOCK();
	/*
	 * temporarily terminate string component
	 */
	heldchar = cnp->cn_nameptr[cnp->cn_namelen];
	cnp->cn_nameptr[cnp->cn_namelen] = '\0';

	nodename = dev_findname(dir_node, cnp->cn_nameptr);
	/*
	 * restore saved character
	 */
	cnp->cn_nameptr[cnp->cn_namelen] = heldchar;

	if (nodename) {
		/* entry exists */
		node = nodename->de_dnp;

		/* Do potential vnode allocation here inside the lock
		 * to make sure that our device node has a non-NULL dn_vn
		 * associated with it.  The device node might otherwise
		 * get deleted out from under us (see devfs_dn_free()).
		 */
		error = devfs_dntovn(node, result_vnode, p);
	}
	DEVFS_UNLOCK();

	if (error) {
		if (error == EAGAIN) {
			goto retry;
		}
		return error;
	}
	if (!nodename) {
		/*
		 * we haven't called devfs_dntovn if we get here
		 * we have not taken a reference on the node.. no
		 * vnode_put is necessary on these error returns
		 *
		 * If it doesn't exist and we're not the last component,
		 * or we're at the last component, but we're not creating
		 * or renaming, return ENOENT.
		 */
		if (!(flags & ISLASTCN) || !(op == CREATE || op == RENAME)) {
			return ENOENT;
		}
		/*
		 * We return with the directory locked, so that
		 * the parameters we set up above will still be
		 * valid if we actually decide to add a new entry.
		 * We return ni_vp == NULL to indicate that the entry
		 * does not currently exist; we leave a pointer to
		 * the (locked) directory vnode in namei_data->ni_dvp.
		 *
		 * NB - if the directory is unlocked, then this
		 * information cannot be used.
		 */
		return EJUSTRETURN;
	}
	/*
	 * from this point forward, we need to vnode_put the reference
	 * picked up in devfs_dntovn if we decide to return an error
	 */

	/*
	 * If deleting, and at end of pathname, return
	 * parameters which can be used to remove file.
	 * If the wantparent flag isn't set, we return only
	 * the directory (in namei_data->ni_dvp), otherwise we go
	 * on and lock the node, being careful with ".".
	 */
	if (op == DELETE && (flags & ISLASTCN)) {
		/*
		 * we are trying to delete '.'.  What does this mean? XXX
		 */
		if (dir_node == node) {
			if (*result_vnode) {
				vnode_put(*result_vnode);
				*result_vnode = NULL;
			}
			if (((error = vnode_get(dir_vnode)) == 0)) {
				*result_vnode = dir_vnode;
			}
			return error;
		}
		return 0;
	}

	/*
	 * If rewriting (RENAME), return the vnode and the
	 * information required to rewrite the present directory
	 * Must get node of directory entry to verify it's a
	 * regular file, or empty directory.
	 */
	if (op == RENAME && wantparent && (flags & ISLASTCN)) {
		/*
		 * Careful about locking second node.
		 * This can only occur if the target is ".".
		 */
		if (dir_node == node) {
			error = EISDIR;
			goto drop_ref;
		}
		return 0;
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
	if ((flags & ISDOTDOT) == 0 && dir_node == node) {
		if (*result_vnode) {
			vnode_put(*result_vnode);
			*result_vnode = NULL;
		}
		if ((error = vnode_get(dir_vnode))) {
			return error;
		}
		*result_vnode = dir_vnode;
	}
	return 0;

drop_ref:
	if (*result_vnode) {
		vnode_put(*result_vnode);
		*result_vnode = NULL;
	}
	return error;
}

static int
devfs_getattr(struct vnop_getattr_args *ap)
/*struct vnop_getattr_args {
 *       struct vnode *a_vp;
 *       struct vnode_attr *a_vap;
 *       kauth_cred_t a_cred;
 *       struct proc *a_p;
 *  } */
{
	struct vnode *vp = ap->a_vp;
	struct vnode_attr *vap = ap->a_vap;
	devnode_t *     file_node;
	struct timeval now;


	DEVFS_LOCK();
	file_node = VTODN(vp);

	VATTR_RETURN(vap, va_mode, file_node->dn_mode);

	/*
	 * Note: for DEV_CDEV and DEV_BDEV, we return the device from
	 * the vp, not the file_node; if we getting information on a
	 * cloning device, we want the cloned information, not the template.
	 */
	switch (file_node->dn_type) {
	case    DEV_DIR:
#if FDESC
	case    DEV_DEVFD:      /* Like a directory */
#endif /* FDESC */
		VATTR_RETURN(vap, va_rdev, 0);
		vap->va_mode |= (S_IFDIR);
		break;
	case    DEV_CDEV:
		VATTR_RETURN(vap, va_rdev, vp->v_rdev);
		vap->va_mode |= (S_IFCHR);
		break;
	case    DEV_BDEV:
		VATTR_RETURN(vap, va_rdev, vp->v_rdev);
		vap->va_mode |= (S_IFBLK);
		break;
	case    DEV_SLNK:
		VATTR_RETURN(vap, va_rdev, 0);
		vap->va_mode |= (S_IFLNK);
		break;
	default:
		VATTR_RETURN(vap, va_rdev, 0);  /* default value only */
	}
	VATTR_RETURN(vap, va_type, vp->v_type);
	VATTR_RETURN(vap, va_nlink, file_node->dn_links);
	VATTR_RETURN(vap, va_uid, file_node->dn_uid);
	VATTR_RETURN(vap, va_gid, file_node->dn_gid);
	VATTR_RETURN(vap, va_fsid, (uintptr_t)file_node->dn_dvm);
	VATTR_RETURN(vap, va_fileid, (uintptr_t)file_node->dn_ino);
	VATTR_RETURN(vap, va_data_size, file_node->dn_len);

	/* return an override block size (advisory) */
	if (vp->v_type == VBLK) {
		VATTR_RETURN(vap, va_iosize, BLKDEV_IOSIZE);
	} else if (vp->v_type == VCHR) {
		VATTR_RETURN(vap, va_iosize, MAXPHYSIO);
	} else {
		VATTR_RETURN(vap, va_iosize, vp->v_mount->mnt_vfsstat.f_iosize);
	}


	DEVFS_ATTR_LOCK_SPIN();

	microtime(&now);
	dn_times_locked(file_node, &now, &now, &now, 0);

	/* if the time is bogus, set it to the boot time */
	if (file_node->dn_ctime.tv_sec == 0) {
		file_node->dn_ctime.tv_sec = boottime_sec();
		file_node->dn_ctime.tv_nsec = 0;
	}
	if (file_node->dn_mtime.tv_sec == 0) {
		file_node->dn_mtime = file_node->dn_ctime;
	}
	if (file_node->dn_atime.tv_sec == 0) {
		file_node->dn_atime = file_node->dn_ctime;
	}
	VATTR_RETURN(vap, va_change_time, file_node->dn_ctime);
	VATTR_RETURN(vap, va_modify_time, file_node->dn_mtime);
	VATTR_RETURN(vap, va_access_time, file_node->dn_atime);

	DEVFS_ATTR_UNLOCK();

	VATTR_RETURN(vap, va_gen, 0);
	VATTR_RETURN(vap, va_filerev, 0);
	VATTR_RETURN(vap, va_acl, NULL);

	/* Hide the root so Finder doesn't display it */
	if (vnode_isvroot(vp)) {
		VATTR_RETURN(vap, va_flags, UF_HIDDEN);
	} else {
		VATTR_RETURN(vap, va_flags, 0);
	}

	DEVFS_UNLOCK();

	return 0;
}

static int
devfs_setattr(struct vnop_setattr_args *ap)
/*struct vnop_setattr_args  {
 *  struct vnode *a_vp;
 *  struct vnode_attr *a_vap;
 *  vfs_context_t a_context;
 *  } */
{
	struct vnode *vp = ap->a_vp;
	struct vnode_attr *vap = ap->a_vap;
	int error = 0;
	devnode_t *     file_node;
	struct timeval atimeval, mtimeval;

	DEVFS_LOCK();

	file_node = VTODN(vp);
	/*
	 * Go through the fields and update if set.
	 */
	if (VATTR_IS_ACTIVE(vap, va_access_time) || VATTR_IS_ACTIVE(vap, va_modify_time)) {
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			file_node->dn_access = 1;
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			file_node->dn_change = 1;
			file_node->dn_update = 1;
		}
		atimeval.tv_sec = vap->va_access_time.tv_sec;
		atimeval.tv_usec = vap->va_access_time.tv_nsec / 1000;
		mtimeval.tv_sec = vap->va_modify_time.tv_sec;
		mtimeval.tv_usec = vap->va_modify_time.tv_nsec / 1000;

		if ((error = devfs_update(vp, &atimeval, &mtimeval))) {
			goto exit;
		}
	}
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_change_time);

	/*
	 * Change the permissions.
	 */
	if (VATTR_IS_ACTIVE(vap, va_mode)) {
		file_node->dn_mode &= ~07777;
		file_node->dn_mode |= vap->va_mode & 07777;
	}
	VATTR_SET_SUPPORTED(vap, va_mode);

	/*
	 * Change the owner.
	 */
	if (VATTR_IS_ACTIVE(vap, va_uid)) {
		file_node->dn_uid = vap->va_uid;
	}
	VATTR_SET_SUPPORTED(vap, va_uid);

	/*
	 * Change the group.
	 */
	if (VATTR_IS_ACTIVE(vap, va_gid)) {
		file_node->dn_gid = vap->va_gid;
	}
	VATTR_SET_SUPPORTED(vap, va_gid);
exit:
	DEVFS_UNLOCK();

	return error;
}

#if CONFIG_MACF
static int
devfs_setlabel(struct vnop_setlabel_args *ap)
/* struct vnop_setlabel_args {
 *               struct vnodeop_desc *a_desc;
 *               struct vnode *a_vp;
 *               struct label *a_vl;
 *       vfs_context_t a_context;
 *       } */
{
	struct vnode *vp;
	struct devnode *de;

	vp = ap->a_vp;
	de = VTODN(vp);

	mac_vnode_label_update(ap->a_context, vp, ap->a_vl);
	mac_devfs_label_update(vp->v_mount, de, vp);

	return 0;
}
#endif

static int
devfs_read(struct vnop_read_args *ap)
/* struct vnop_read_args {
 *       struct vnode *a_vp;
 *       struct uio *a_uio;
 *       int  a_ioflag;
 *       vfs_context_t a_context;
 *  } */
{
	devnode_t * dn_p = VTODN(ap->a_vp);

	switch (ap->a_vp->v_type) {
	case VDIR: {
		dn_p->dn_access = 1;

		return VNOP_READDIR(ap->a_vp, ap->a_uio, 0, NULL, NULL, ap->a_context);
	}
	default: {
		printf("devfs_read(): bad file type %d", ap->a_vp->v_type);
		return EINVAL;
	}
	}
}

static int
devfs_close(struct vnop_close_args *ap)
/* struct vnop_close_args {
 *       struct vnode *a_vp;
 *       int  a_fflag;
 *       vfs_context_t a_context;
 *  } */
{
	struct vnode *          vp = ap->a_vp;
	devnode_t *     dnp;

	if (vnode_isinuse(vp, 1)) {
		DEVFS_LOCK();
		dnp = VTODN(vp);
		if (dnp) {
			dn_times_now(dnp, 0);
		}
		DEVFS_UNLOCK();
	}
	return 0;
}

static int
devfsspec_close(struct vnop_close_args *ap)
/* struct vnop_close_args {
 *       struct vnode *a_vp;
 *       int  a_fflag;
 *       vfs_context_t a_context;
 *  } */
{
	struct vnode *          vp = ap->a_vp;
	devnode_t *     dnp;

	if (vnode_isinuse(vp, 0)) {
		DEVFS_LOCK();
		dnp = VTODN(vp);
		if (dnp) {
			dn_times_now(dnp, 0);
		}
		DEVFS_UNLOCK();
	}

	return VOCALL(spec_vnodeop_p, VOFFSET(vnop_close), ap);
}

static boolean_t
devfs_update_needed(long now_s, long last_s)
{
	if (now_s > last_s) {
		if (now_s - last_s >= DEVFS_LAZY_UPDATE_SECONDS) {
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Given a set of time updates required [to happen at some point], check
 * either make those changes (and resolve other pending updates) or mark
 * the devnode for a subsequent update.
 */
static void
devfs_consider_time_update(devnode_t *dnp, uint32_t just_changed_flags)
{
	struct timeval          now;
	long now_s;

	microtime(&now);
	now_s = now.tv_sec;

	if (dnp->dn_change || (just_changed_flags & DEVFS_UPDATE_CHANGE)) {
		if (devfs_update_needed(now_s, dnp->dn_ctime.tv_sec)) {
			dn_times_now(dnp, just_changed_flags);
			return;
		}
	}
	if (dnp->dn_access || (just_changed_flags & DEVFS_UPDATE_ACCESS)) {
		if (devfs_update_needed(now_s, dnp->dn_atime.tv_sec)) {
			dn_times_now(dnp, just_changed_flags);
			return;
		}
	}
	if (dnp->dn_update || (just_changed_flags & DEVFS_UPDATE_MOD)) {
		if (devfs_update_needed(now_s, dnp->dn_mtime.tv_sec)) {
			dn_times_now(dnp, just_changed_flags);
			return;
		}
	}

	/* Not going to do anything now--mark for later update */
	dn_mark_for_delayed_times_update(dnp, just_changed_flags);

	return;
}

static int
devfsspec_read(struct vnop_read_args *ap)
/* struct vnop_read_args {
 *       struct vnode *a_vp;
 *       struct uio *a_uio;
 *       int  a_ioflag;
 *       kauth_cred_t a_cred;
 *  } */
{
	devnode_t *     dnp = VTODN(ap->a_vp);

	devfs_consider_time_update(dnp, DEVFS_UPDATE_ACCESS);

	return VOCALL(spec_vnodeop_p, VOFFSET(vnop_read), ap);
}

static int
devfsspec_write(struct vnop_write_args *ap)
/* struct vnop_write_args  {
 *       struct vnode *a_vp;
 *       struct uio *a_uio;
 *       int  a_ioflag;
 *       vfs_context_t a_context;
 *  } */
{
	devnode_t *     dnp = VTODN(ap->a_vp);

	devfs_consider_time_update(dnp, DEVFS_UPDATE_CHANGE | DEVFS_UPDATE_MOD);

	return VOCALL(spec_vnodeop_p, VOFFSET(vnop_write), ap);
}

/*
 *  Write data to a file or directory.
 */
static int
devfs_write(struct vnop_write_args *ap)
/* struct vnop_write_args  {
 *       struct vnode *a_vp;
 *       struct uio *a_uio;
 *       int  a_ioflag;
 *       kauth_cred_t a_cred;
 *  } */
{
	switch (ap->a_vp->v_type) {
	case VDIR:
		return EISDIR;
	default:
		printf("devfs_write(): bad file type %d", ap->a_vp->v_type);
		return EINVAL;
	}
}

/*
 * Deviates from UFS naming convention because there is a KPI function
 * called devfs_remove().
 */
static int
devfs_vnop_remove(struct vnop_remove_args *ap)
/* struct vnop_remove_args  {
 *       struct vnode *a_dvp;
 *       struct vnode *a_vp;
 *       struct componentname *a_cnp;
 *  } */
{
	struct vnode *vp = ap->a_vp;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	devnode_t *  tp;
	devnode_t *  tdp;
	devdirent_t * tnp;
	int doingdirectory = 0;
	int error = 0;

	/*
	 * assume that the name is null terminated as they
	 * are the end of the path. Get pointers to all our
	 * devfs structures.
	 */

	DEVFS_LOCK();

	tp = VTODN(vp);
	tdp = VTODN(dvp);


	tnp = dev_findname(tdp, cnp->cn_nameptr);

	if (tnp == NULL) {
		error = ENOENT;
		goto abort;
	}

	/*
	 * Don't allow removing critical devfs devices
	 */
	if (devfs_is_name_protected(dvp, cnp->cn_nameptr)) {
		error = EINVAL;
		goto abort;
	}

	/*
	 * Make sure that we don't try do something stupid
	 */
	if ((tp->dn_type) == DEV_DIR) {
		/*
		 * Avoid ".", "..", and aliases of "." for obvious reasons.
		 */
		if ((cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.')
		    || (cnp->cn_flags & ISDOTDOT)) {
			error = EINVAL;
			goto abort;
		}
		doingdirectory++;
	}

	/***********************************
	* Start actually doing things.... *
	***********************************/
	devfs_consider_time_update(tdp, DEVFS_UPDATE_CHANGE | DEVFS_UPDATE_MOD);

	/*
	 * Target must be empty if a directory and have no links
	 * to it. Also, ensure source and target are compatible
	 * (both directories, or both not directories).
	 */
	if ((doingdirectory) && (tp->dn_links > 2)) {
		error = ENOTEMPTY;
		goto abort;
	}
	dev_free_name(tnp);
abort:
	DEVFS_UNLOCK();

	return error;
}

/*
 */
static int
devfs_link(struct vnop_link_args *ap)
/*struct vnop_link_args  {
 *       struct vnode *a_tdvp;
 *       struct vnode *a_vp;
 *       struct componentname *a_cnp;
 *       vfs_context_t a_context;
 *  } */
{
	struct vnode *vp = ap->a_vp;
	struct vnode *tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;
	devnode_t * fp;
	devnode_t * tdp;
	devdirent_t * tnp;
	int error = 0;

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
	/* can lookup dnode safely for tdvp outside of devfs lock as it is not aliased */
	tdp = VTODN(tdvp);

	if (tdvp->v_mount != vp->v_mount) {
		return EXDEV;
	}
	DEVFS_LOCK();

	fp = VTODN(vp);

	/***********************************
	* Start actually doing things.... *
	***********************************/
	dn_times_now(fp, DEVFS_UPDATE_CHANGE);

	if (!error) {
		error = dev_add_name(cnp->cn_nameptr, tdp, NULL, fp, &tnp);
	}
out1:
	DEVFS_UNLOCK();

	return error;
}

/*
 * Rename system call. Seems overly complicated to me...
 *      rename("foo", "bar");
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
devfs_rename(struct vnop_rename_args *ap)
/*struct vnop_rename_args  {
 *       struct vnode *a_fdvp;
 *       struct vnode *a_fvp;
 *       struct componentname *a_fcnp;
 *       struct vnode *a_tdvp;
 *       struct vnode *a_tvp;
 *       struct componentname *a_tcnp;
 *       vfs_context_t a_context;
 *  } */
{
	struct vnode *tvp = ap->a_tvp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *fdvp = ap->a_fdvp;
	struct componentname *tcnp = ap->a_tcnp;
	struct componentname *fcnp = ap->a_fcnp;
	devnode_t *fp, *fdp, *tp, *tdp;
	devdirent_t *fnp, *tnp;
	int doingdirectory = 0;
	int error = 0;

	DEVFS_LOCK();
	/*
	 * First catch an arbitrary restriction for this FS
	 */
	if (tcnp->cn_namelen > DEVMAXNAMESIZE) {
		error = ENAMETOOLONG;
		goto out;
	}

	/*
	 * assume that the names are null terminated as they
	 * are the end of the path. Get pointers to all our
	 * devfs structures.
	 */
	tdp = VTODN(tdvp);
	fdp = VTODN(fdvp);
	fp = VTODN(fvp);

	fnp = dev_findname(fdp, fcnp->cn_nameptr);

	if (fnp == NULL) {
		error = ENOENT;
		goto out;
	}
	tp = NULL;
	tnp = NULL;

	if (tvp) {
		tnp = dev_findname(tdp, tcnp->cn_nameptr);

		if (tnp == NULL) {
			error = ENOENT;
			goto out;
		}
		tp = VTODN(tvp);
	}

	/*
	 * Make sure that we don't try do something stupid
	 */
	if ((fp->dn_type) == DEV_DIR) {
		/*
		 * Avoid ".", "..", and aliases of "." for obvious reasons.
		 */
		if ((fcnp->cn_namelen == 1 && fcnp->cn_nameptr[0] == '.')
		    || (fcnp->cn_flags & ISDOTDOT)
		    || (tcnp->cn_namelen == 1 && tcnp->cn_nameptr[0] == '.')
		    || (tcnp->cn_flags & ISDOTDOT)
		    || (tdp == fp)) {
			error = EINVAL;
			goto out;
		}
		doingdirectory++;
	}

	/*
	 * Don't allow renaming critical devfs devices
	 */
	if (devfs_is_name_protected(fdvp, fcnp->cn_nameptr) ||
	    devfs_is_name_protected(tdvp, tcnp->cn_nameptr)) {
		error = EINVAL;
		goto out;
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
		tmp = tdp;
		do {
			if (tmp == fp) {
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
	dn_times_now(fp, DEVFS_UPDATE_CHANGE);

	/*
	 * Check if just deleting a link name.
	 */
	if (fvp == tvp) {
		if (fvp->v_type == VDIR) {
			error = EINVAL;
			goto out;
		}
		/* Release destination completely. */
		dev_free_name(fnp);

		DEVFS_UNLOCK();
		return 0;
	}
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
		/*
		 * Target must be empty if a directory and have no links
		 * to it. Also, ensure source and target are compatible
		 * (both directories, or both not directories).
		 */
		if ((doingdirectory) && (tp->dn_links > 2)) {
			error = ENOTEMPTY;
			goto bad;
		}
		dev_free_name(tnp);
		tp = NULL;
	}
	dev_add_name(tcnp->cn_nameptr, tdp, NULL, fp, &tnp);
	fnp->de_dnp = NULL;
	fp->dn_links--; /* one less link to it.. */

	dev_free_name(fnp);
bad:
	fp->dn_links--; /* we added one earlier*/
out:
	DEVFS_UNLOCK();
	return error;
}

static int
devfs_mkdir(struct vnop_mkdir_args *ap)
/*struct vnop_mkdir_args {
 *       struct vnode *a_dvp;
 *       struct vnode **a_vpp;
 *       struct componentname *a_cnp;
 *       struct vnode_attr *a_vap;
 *       vfs_context_t a_context;
 *  } */
{
	struct componentname * cnp = ap->a_cnp;
	vfs_context_t ctx = cnp->cn_context;
	struct proc *p = vfs_context_proc(ctx);
	int error = 0;
	devnode_t * dir_p;
	devdirent_t * nm_p;
	devnode_t * dev_p;
	struct vnode_attr *     vap = ap->a_vap;
	struct vnode * * vpp = ap->a_vpp;

	DEVFS_LOCK();

	dir_p = VTODN(ap->a_dvp);
	error = dev_add_entry(cnp->cn_nameptr, dir_p, DEV_DIR,
	    NULL, NULL, NULL, &nm_p);
	if (error) {
		goto failure;
	}
	dev_p = nm_p->de_dnp;
	dev_p->dn_uid = dir_p->dn_uid;
	dev_p->dn_gid = dir_p->dn_gid;
	dev_p->dn_mode = vap->va_mode;
	dn_copy_times(dev_p, dir_p);

	error = devfs_dntovn(dev_p, vpp, p);
failure:
	DEVFS_UNLOCK();

	return error;
}

/*
 * An rmdir is a special type of remove, which we already support; we wrap
 * and reexpress the arguments to call devfs_remove directly.  The only
 * different argument is flags, which we do not set, since it's ignored.
 */
static int
devfs_rmdir(struct vnop_rmdir_args *ap)
/* struct vnop_rmdir_args {
 *       struct vnode *a_dvp;
 *       struct vnode *a_vp;
 *       struct componentname *a_cnp;
 *       vfs_context_t a_context;
 *  } */
{
	struct vnop_remove_args ra;

	ra.a_dvp = ap->a_dvp;
	ra.a_vp = ap->a_vp;
	ra.a_cnp = ap->a_cnp;
	ra.a_flags = 0;         /* XXX */
	ra.a_context = ap->a_context;

	return devfs_vnop_remove(&ra);
}


static int
devfs_symlink(struct vnop_symlink_args *ap)
/*struct vnop_symlink_args {
 *       struct vnode *a_dvp;
 *       struct vnode **a_vpp;
 *       struct componentname *a_cnp;
 *       struct vnode_attr *a_vap;
 *       char *a_target;
 *       vfs_context_t a_context;
 *  } */
{
	int error;
	devdirent_t *newent;

	DEVFS_LOCK();
	error = devfs_make_symlink(VTODN(ap->a_dvp), ap->a_cnp->cn_nameptr, ap->a_vap->va_mode, ap->a_target, &newent);

	if (error == 0) {
		error = devfs_dntovn(newent->de_dnp, ap->a_vpp, vfs_context_proc(ap->a_context));
	}

	DEVFS_UNLOCK();

	return error;
}

/* Called with devfs locked */
int
devfs_make_symlink(devnode_t *dir_p, char *name, int mode, char *target, devdirent_t **newent)
{
	int error = 0;
	devnode_type_t typeinfo;
	devdirent_t * nm_p;
	devnode_t * dev_p;

	typeinfo.Slnk.name = target;
	typeinfo.Slnk.namelen = strlen(target);

	error = dev_add_entry(name, dir_p, DEV_SLNK,
	    &typeinfo, NULL, NULL, &nm_p);
	if (error) {
		goto failure;
	}
	dev_p = nm_p->de_dnp;
	dev_p->dn_uid = dir_p->dn_uid;
	dev_p->dn_gid = dir_p->dn_gid;
	dev_p->dn_mode = mode;
	dn_copy_times(dev_p, dir_p);

	if (newent) {
		*newent = nm_p;
	}

failure:

	return error;
}

/*
 * Mknod vnode call
 */
static int
devfs_mknod(struct vnop_mknod_args *ap)
/* struct vnop_mknod_args {
 *       struct vnode *a_dvp;
 *       struct vnode **a_vpp;
 *       struct componentname *a_cnp;
 *       struct vnode_attr *a_vap;
 *       vfs_context_t a_context;
 *  } */
{
	struct componentname * cnp = ap->a_cnp;
	vfs_context_t ctx = cnp->cn_context;
	struct proc *p = vfs_context_proc(ctx);
	devnode_t *     dev_p;
	devdirent_t *   devent;
	devnode_t *     dir_p;  /* devnode for parent directory */
	struct vnode *  dvp = ap->a_dvp;
	int             error = 0;
	devnode_type_t  typeinfo;
	struct vnode_attr *     vap = ap->a_vap;
	struct vnode ** vpp = ap->a_vpp;

	*vpp = NULL;
	if (!(vap->va_type == VBLK) && !(vap->va_type == VCHR)) {
		return EINVAL; /* only support mknod of special files */
	}
	typeinfo.dev = vap->va_rdev;

	DEVFS_LOCK();

	dir_p = VTODN(dvp);

	error = dev_add_entry(cnp->cn_nameptr, dir_p,
	    (vap->va_type == VBLK) ? DEV_BDEV : DEV_CDEV,
	    &typeinfo, NULL, NULL, &devent);
	if (error) {
		goto failure;
	}
	dev_p = devent->de_dnp;
	error = devfs_dntovn(dev_p, vpp, p);
	if (error) {
		goto failure;
	}
	dev_p->dn_uid = vap->va_uid;
	dev_p->dn_gid = vap->va_gid;
	dev_p->dn_mode = vap->va_mode;
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	VATTR_SET_SUPPORTED(vap, va_mode);
failure:
	DEVFS_UNLOCK();

	return error;
}

/*
 * Vnode op for readdir
 */
static int
devfs_readdir(struct vnop_readdir_args *ap)
/*struct vnop_readdir_args {
 *       struct vnode *a_vp;
 *       struct uio *a_uio;
 *       int a_flags;
 *       int *a_eofflag;
 *       int *a_numdirent;
 *       vfs_context_t a_context;
 *  } */
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct dirent dirent;
	devnode_t * dir_node;
	devdirent_t *   name_node;
	const char *name;
	int error = 0;
	int reclen;
	int nodenumber;
	int     startpos, pos;

	if (ap->a_flags & (VNODE_READDIR_EXTENDED | VNODE_READDIR_REQSEEKOFF)) {
		return EINVAL;
	}

	/*  set up refs to dir */
	dir_node = VTODN(vp);
	if (dir_node->dn_type != DEV_DIR) {
		return ENOTDIR;
	}
	pos = 0;
	startpos = uio->uio_offset;

	DEVFS_LOCK();

	name_node = dir_node->dn_typeinfo.Dir.dirlist;
	nodenumber = 0;

	while ((name_node || (nodenumber < 2)) && (uio_resid(uio) > 0)) {
		switch (nodenumber) {
		case    0:
			dirent.d_fileno = dir_node->dn_ino;
			name = ".";
			dirent.d_namlen = 1;
			dirent.d_type = DT_DIR;
			break;
		case    1:
			if (dir_node->dn_typeinfo.Dir.parent) {
				dirent.d_fileno = dir_node->dn_typeinfo.Dir.parent->dn_ino;
			} else {
				dirent.d_fileno = dir_node->dn_ino;
			}
			name = "..";
			dirent.d_namlen = 2;
			dirent.d_type = DT_DIR;
			break;
		default:
			dirent.d_fileno = name_node->de_dnp->dn_ino;
			dirent.d_namlen = strlen(name_node->de_name);
			name = name_node->de_name;
			switch (name_node->de_dnp->dn_type) {
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
#define GENERIC_DIRSIZ(dp) \
    ((sizeof (struct dirent) - (MAXNAMLEN+1)) + (((dp)->d_namlen+1 + 3) &~ 3))

		reclen = dirent.d_reclen = GENERIC_DIRSIZ(&dirent);

		if (pos >= startpos) {   /* made it to the offset yet? */
			if (uio_resid(uio) < reclen) { /* will it fit? */
				break;
			}
			strlcpy(dirent.d_name, name, DEVMAXNAMESIZE);
			if ((error = uiomove((caddr_t)&dirent,
			    dirent.d_reclen, uio)) != 0) {
				break;
			}
		}
		pos += reclen;
		if ((nodenumber > 1) && name_node) {
			name_node = name_node->de_next;
		}
		nodenumber++;
	}
	DEVFS_UNLOCK();
	uio->uio_offset = pos;

	devfs_consider_time_update(dir_node, DEVFS_UPDATE_ACCESS);

	return error;
}


/*
 */
static int
devfs_readlink(struct vnop_readlink_args *ap)
/*struct vnop_readlink_args {
 *       struct vnode *a_vp;
 *       struct uio *a_uio;
 *       vfs_context_t a_context;
 *  } */
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	devnode_t * lnk_node;
	int error = 0;

	/*  set up refs to dir */
	lnk_node = VTODN(vp);

	if (lnk_node->dn_type != DEV_SLNK) {
		error = EINVAL;
		goto out;
	}
	error = uiomove(lnk_node->dn_typeinfo.Slnk.name,
	    lnk_node->dn_typeinfo.Slnk.namelen, uio);
out:
	return error;
}

static int
devfs_reclaim(struct vnop_reclaim_args *ap)
/*struct vnop_reclaim_args {
 *       struct vnode *a_vp;
 *  } */
{
	struct vnode *      vp = ap->a_vp;
	devnode_t *         dnp;

	DEVFS_LOCK();

	dnp = VTODN(vp);

	if (dnp) {
		/* If this is a cloning device, it didn't have a dn_vn anyway */
		dnp->dn_vn = NULL;
		vnode_clearfsnode(vp);

		/* This could delete the node, if we are the last vnode */
		devfs_rele_node(dnp);
	}
	DEVFS_UNLOCK();

	return 0;
}


/*
 * Get configurable pathname variables.
 */
static int
devs_vnop_pathconf(
	struct vnop_pathconf_args /* {
                                   *  struct vnode *a_vp;
                                   *  int a_name;
                                   *  int *a_retval;
                                   *  vfs_context_t a_context;
                                   *  } */*ap)
{
	switch (ap->a_name) {
	case _PC_LINK_MAX:
		/* arbitrary limit matching HFS; devfs has no hard limit */
		*ap->a_retval = 32767;
		break;
	case _PC_NAME_MAX:
		*ap->a_retval = DEVMAXNAMESIZE - 1;     /* includes NUL */
		break;
	case _PC_PATH_MAX:
		*ap->a_retval = DEVMAXPATHSIZE - 1;     /* XXX nonconformant */
		break;
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 200112;         /* _POSIX_CHOWN_RESTRICTED */
		break;
	case _PC_NO_TRUNC:
		*ap->a_retval = 0;
		break;
	case _PC_CASE_SENSITIVE:
		*ap->a_retval = 1;
		break;
	case _PC_CASE_PRESERVING:
		*ap->a_retval = 1;
		break;
	default:
		return EINVAL;
	}

	return 0;
}



/**************************************************************************\
* pseudo ops *
\**************************************************************************/

/*
 *
 *	struct vnop_inactive_args {
 *		struct vnode *a_vp;
 *		vfs_context_t a_context;
 *	}
 */

static int
devfs_inactive(__unused struct vnop_inactive_args *ap)
{
	vnode_t vp = ap->a_vp;
	devnode_t *dnp = VTODN(vp);

	/*
	 * Cloned vnodes are not linked in anywhere, so they
	 * can just be recycled.
	 */
	if (dnp->dn_clone != NULL) {
		vnode_recycle(vp);
	}

	return 0;
}

/*
 * called with DEVFS_LOCK held
 */
static int
devfs_update(struct vnode *vp, struct timeval *access, struct timeval *modify)
{
	devnode_t * ip;
	struct timeval now;

	ip = VTODN(vp);
	if (vp->v_mount->mnt_flag & MNT_RDONLY) {
		ip->dn_access = 0;
		ip->dn_change = 0;
		ip->dn_update = 0;

		return 0;
	}

	DEVFS_ATTR_LOCK_SPIN();
	microtime(&now);
	dn_times_locked(ip, access, modify, &now, DEVFS_UPDATE_ACCESS | DEVFS_UPDATE_MOD);
	DEVFS_ATTR_UNLOCK();

	return 0;
}

#define VOPFUNC int (*)(void *)

/* The following ops are used by directories and symlinks */
int(**devfs_vnodeop_p)(void *);
static struct vnodeopv_entry_desc devfs_vnodeop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)devfs_lookup },           /* lookup */
	{ &vnop_create_desc, (VOPFUNC)err_create },             /* create */
	{ &vnop_whiteout_desc, (VOPFUNC)err_whiteout },         /* whiteout */
	{ &vnop_mknod_desc, (VOPFUNC)devfs_mknod },             /* mknod */
	{ &vnop_open_desc, (VOPFUNC)nop_open },                 /* open */
	{ &vnop_close_desc, (VOPFUNC)devfs_close },             /* close */
	{ &vnop_getattr_desc, (VOPFUNC)devfs_getattr },         /* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)devfs_setattr },         /* setattr */
	{ &vnop_read_desc, (VOPFUNC)devfs_read },               /* read */
	{ &vnop_write_desc, (VOPFUNC)devfs_write },             /* write */
	{ &vnop_ioctl_desc, (VOPFUNC)err_ioctl },               /* ioctl */
	{ &vnop_select_desc, (VOPFUNC)err_select },             /* select */
	{ &vnop_revoke_desc, (VOPFUNC)err_revoke },             /* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)err_mmap },                 /* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)nop_fsync },               /* fsync */
	{ &vnop_remove_desc, (VOPFUNC)devfs_vnop_remove },      /* remove */
	{ &vnop_link_desc, (VOPFUNC)devfs_link },               /* link */
	{ &vnop_rename_desc, (VOPFUNC)devfs_rename },           /* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)devfs_mkdir },             /* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)devfs_rmdir },             /* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)devfs_symlink },         /* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)devfs_readdir },         /* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)devfs_readlink },       /* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)devfs_inactive },       /* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)devfs_reclaim },         /* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)err_strategy },         /* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)devs_vnop_pathconf },   /* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)err_advlock },           /* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)err_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)err_pagein },             /* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)err_pageout },           /* Pageout */
	{ &vnop_copyfile_desc, (VOPFUNC)err_copyfile },         /* Copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC)err_blktooff },         /* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)err_offtoblk },         /* offtoblk */
	{ &vnop_blockmap_desc, (VOPFUNC)err_blockmap },         /* blockmap */
#if CONFIG_MACF
	{ &vnop_setlabel_desc, (VOPFUNC)devfs_setlabel },       /* setlabel */
#endif
	{ (struct vnodeop_desc*)NULL, (int (*)(void *))NULL }
};
struct vnodeopv_desc devfs_vnodeop_opv_desc =
{ &devfs_vnodeop_p, devfs_vnodeop_entries };

/* The following ops are used by the device nodes */
int(**devfs_spec_vnodeop_p)(void *);
static struct vnodeopv_entry_desc devfs_spec_vnodeop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)spec_lookup },            /* lookup */
	{ &vnop_create_desc, (VOPFUNC)spec_create },            /* create */
	{ &vnop_mknod_desc, (VOPFUNC)spec_mknod },              /* mknod */
	{ &vnop_open_desc, (VOPFUNC)spec_open },                        /* open */
	{ &vnop_close_desc, (VOPFUNC)devfsspec_close },         /* close */
	{ &vnop_getattr_desc, (VOPFUNC)devfs_getattr },         /* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)devfs_setattr },         /* setattr */
	{ &vnop_read_desc, (VOPFUNC)devfsspec_read },           /* read */
	{ &vnop_write_desc, (VOPFUNC)devfsspec_write },         /* write */
	{ &vnop_ioctl_desc, (VOPFUNC)spec_ioctl },              /* ioctl */
	{ &vnop_select_desc, (VOPFUNC)spec_select },            /* select */
	{ &vnop_revoke_desc, (VOPFUNC)spec_revoke },            /* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)spec_mmap },                        /* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)spec_fsync },              /* fsync */
	{ &vnop_remove_desc, (VOPFUNC)devfs_vnop_remove },      /* remove */
	{ &vnop_link_desc, (VOPFUNC)devfs_link },               /* link */
	{ &vnop_rename_desc, (VOPFUNC)spec_rename },            /* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)spec_mkdir },              /* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)spec_rmdir },              /* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)spec_symlink },          /* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)spec_readdir },          /* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)spec_readlink },                /* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)devfs_inactive },       /* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)devfs_reclaim },         /* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)spec_strategy },                /* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)spec_pathconf },                /* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)spec_advlock },          /* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)err_pagein },             /* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)err_pageout },           /* Pageout */
	{ &vnop_copyfile_desc, (VOPFUNC)err_copyfile },         /* Copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC)spec_blktooff },        /* blktooff */
	{ &vnop_blktooff_desc, (VOPFUNC)spec_offtoblk  },       /* blkofftoblk */
	{ &vnop_blockmap_desc, (VOPFUNC)spec_blockmap },        /* blockmap */
#if CONFIG_MACF
	{ &vnop_setlabel_desc, (VOPFUNC)devfs_setlabel },       /* setlabel */
#endif
	{ (struct vnodeop_desc*)NULL, (int (*)(void *))NULL }
};
struct vnodeopv_desc devfs_spec_vnodeop_opv_desc =
{ &devfs_spec_vnodeop_p, devfs_spec_vnodeop_entries };


#if FDESC
int(**devfs_devfd_vnodeop_p)(void*);
static struct vnodeopv_entry_desc devfs_devfd_vnodeop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)devfs_devfd_lookup},      /* lookup */
	{ &vnop_open_desc, (VOPFUNC)nop_open },                 /* open */
	{ &vnop_close_desc, (VOPFUNC)devfs_close },             /* close */
	{ &vnop_getattr_desc, (VOPFUNC)devfs_getattr },         /* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)devfs_setattr },         /* setattr */
	{ &vnop_revoke_desc, (VOPFUNC)err_revoke },             /* revoke */
	{ &vnop_fsync_desc, (VOPFUNC)nop_fsync },               /* fsync */
	{ &vnop_readdir_desc, (VOPFUNC)devfs_devfd_readdir},            /* readdir */
	{ &vnop_inactive_desc, (VOPFUNC)devfs_inactive },       /* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)devfs_reclaim },         /* reclaim */
	{ &vnop_pathconf_desc, (VOPFUNC)devs_vnop_pathconf },   /* pathconf */
#if CONFIG_MACF
	{ &vnop_setlabel_desc, (VOPFUNC)devfs_setlabel },       /* setlabel */
#endif
	{ (struct vnodeop_desc*)NULL, (int (*)(void *))NULL }
};
struct vnodeopv_desc devfs_devfd_vnodeop_opv_desc =
{ &devfs_devfd_vnodeop_p, devfs_devfd_vnodeop_entries};
#endif /* FDESC */
