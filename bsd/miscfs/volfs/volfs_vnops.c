/*
 * Copyright (c) 1998-2004 Apple Computer, Inc. All rights reserved.
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

#include <mach/mach_types.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/proc_internal.h>	/* for p_fd */
#include <sys/kauth.h>
#include <sys/conf.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/namei.h>
#include <sys/attr.h>
#include <sys/kdebug.h>
#include <sys/queue.h>
#include <sys/uio_internal.h>

#include <sys/vm.h>
#include <sys/errno.h>
#include <vfs/vfs_support.h>

#include <kern/locks.h>

#include "volfs.h"

/*
 * volfs acts as a bridge between the requirements of the MacOS API and the Unix API.
 * MacOS applications describe files by a <Volume ID><Directory ID><File Name> triple.
 * The Unix API describes files by pathname.  Volfs is a virtual file system that sits over
 * the HFS VFS interface and allows files to be described by a <Volume ID>/<Directory ID>/<File Name>
 * pathname.
 *
 * The root of the volfs filesystem consists of directories named the volume ID's of all the
 * currently mounted filesystems which support the VFS vget() routine.  Each of those directories
 * supports the lookup by file ID of all files and directories within the filesystem.  When a
 * file or directory is resolved its vnode from that filesystem rather than a volfs vnode is returned
 * allowing immediate access to the target file or directory.
 *
 * Readdir on the root of the volfs filesystem returns the list of available file systems.  Readdir
 * on a filesystem node, however, returns only . and .. since it is not practical to list all
 * of the file ID's in a timely fashion and furthermore VFS does not provide a mechanism for
 * enumerating all of the file id's.
 *
 * Volume ID's are taken from the low 32 bits of the f_fsid field, formatted as a base 10 ASCII
 * string with no leading zeros (volume ID 1 is represented as "1").
 *
 * File ID's are created in same manner, with their 32 bits formatted as a base 10 ASCII
 * string with no leading zeros.
 *
 * Volfs does create a security hole since it is possible to bypass directory permissions higher
 * in the namespace tree.  This security hole is about the same as the one created by NFS which uses
 * a similar mechanism.
 */

static int  volfs_reclaim  (struct vnop_reclaim_args*);
static int  volfs_getattr  (struct vnop_getattr_args *);
static int  volfs_select   (struct vnop_select_args *);
static int  volfs_rmdir    (struct vnop_rmdir_args *);
static int  volfs_readdir  (struct vnop_readdir_args *);
static int  volfs_pathconf (struct vnop_pathconf_args *);
static int  volfs_lookup   (struct vnop_lookup_args *);

static int volfs_readdir_callback(mount_t, void *);
static int get_filevnode(struct mount *parent_fs, u_int id, vnode_t *ret_vnode, vfs_context_t context);
static int get_fsvnode(struct mount *our_mount, int id, vnode_t *ret_vnode);

/* for the call back function in volfs_readdir */
struct volfs_rdstruct {
	int 		validindex;
	vnode_t 	vp;
	int 		rec_offset;
	struct uio * uio;
};

#define VOPFUNC int (*)(void *)

/* Global vfs data structures for volfs. */
int                 (**volfs_vnodeop_p) (void *);
struct vnodeopv_entry_desc volfs_vnodeop_entries[] = {
    {&vnop_default_desc, (VOPFUNC)vn_default_error},
    {&vnop_strategy_desc, (VOPFUNC)err_strategy},	/* strategy */
    {&vnop_bwrite_desc, (VOPFUNC)err_bwrite},		/* bwrite */
    {&vnop_lookup_desc, (VOPFUNC)volfs_lookup},		/* lookup */
    {&vnop_create_desc, (VOPFUNC)err_create},		/* create */
    {&vnop_whiteout_desc, (VOPFUNC)err_whiteout},	/* whiteout */
    {&vnop_mknod_desc, (VOPFUNC)err_mknod},		/* mknod */
    {&vnop_open_desc, (VOPFUNC)nop_open},		/* open */
    {&vnop_close_desc, (VOPFUNC)nop_close},		/* close */
    {&vnop_getattr_desc, (VOPFUNC)volfs_getattr},	/* getattr */
    {&vnop_setattr_desc, (VOPFUNC)err_setattr},		/* setattr */
    {&vnop_getattrlist_desc, (VOPFUNC)err_getattrlist},	/* getattrlist */
    {&vnop_setattrlist_desc, (VOPFUNC)err_setattrlist},	/* setattrlist */
    {&vnop_read_desc, (VOPFUNC)err_read},		/* read */
    {&vnop_write_desc, (VOPFUNC)err_write},		/* write */
    {&vnop_ioctl_desc, (VOPFUNC)err_ioctl},		/* ioctl */
    {&vnop_select_desc, (VOPFUNC)volfs_select},		/* select */
    {&vnop_exchange_desc, (VOPFUNC)err_exchange},	/* exchange */
    {&vnop_revoke_desc, (VOPFUNC)nop_revoke},		/* revoke */
    {&vnop_mmap_desc, (VOPFUNC)err_mmap},		/* mmap */
    {&vnop_fsync_desc, (VOPFUNC)err_fsync},		/* fsync */
    {&vnop_remove_desc, (VOPFUNC)err_remove},		/* remove */
    {&vnop_link_desc, (VOPFUNC)err_link},		/* link */
    {&vnop_rename_desc, (VOPFUNC)err_rename},		/* rename */
    {&vnop_mkdir_desc, (VOPFUNC)err_mkdir},		/* mkdir */
    {&vnop_rmdir_desc, (VOPFUNC)volfs_rmdir},		/* rmdir */
    {&vnop_symlink_desc, (VOPFUNC)err_symlink},		/* symlink */
    {&vnop_readdir_desc, (VOPFUNC)volfs_readdir},	/* readdir */
    {&vnop_readdirattr_desc, (VOPFUNC)err_readdirattr},	/* readdirattr */
    {&vnop_readlink_desc, (VOPFUNC)err_readlink},	/* readlink */
    {&vnop_inactive_desc, (VOPFUNC)err_inactive},	/* inactive */
    {&vnop_reclaim_desc, (VOPFUNC)volfs_reclaim},	/* reclaim */
    {&vnop_pathconf_desc, (VOPFUNC)volfs_pathconf},	/* pathconf */
    {&vnop_advlock_desc, (VOPFUNC)err_advlock},		/* advlock */
    {&vnop_allocate_desc, (VOPFUNC)err_allocate},	/* allocate */
	{&vnop_pagein_desc, (VOPFUNC)err_pagein},	/* pagein */
	{&vnop_pageout_desc, (VOPFUNC)err_pageout},	/* pageout */
	{&vnop_searchfs_desc, (VOPFUNC)err_searchfs},	/* searchfs */
	{&vnop_copyfile_desc, (VOPFUNC)err_copyfile },	/* Copyfile */
	{&vnop_blktooff_desc, (VOPFUNC)err_blktooff},	/* blktooff */
	{&vnop_offtoblk_desc, (VOPFUNC)err_offtoblk },	/* offtoblk */
 	{&vnop_blockmap_desc, (VOPFUNC)err_blockmap },		/* blockmap */
   {(struct vnodeop_desc *) NULL, (int (*) ()) NULL}
};

/*
 * Oh what a tangled web we weave.  This structure will be used by
 * bsd/vfs/vfs_conf.c to actually do the initialization of volfs_vnodeop_p
 */
struct vnodeopv_desc volfs_vnodeop_opv_desc =
{&volfs_vnodeop_p, volfs_vnodeop_entries};

static char gDotDot[] = "..";

struct finfo {
    fsobj_id_t parID;
};

struct finfoattrbuf {
    unsigned long length;
    struct finfo fi;
};


static int volfs_getattr_callback(mount_t, void *);


/*
 * volfs_reclaim - Reclaim a vnode so that it can be used for other purposes.
 */
static int
volfs_reclaim(ap)
    struct vnop_reclaim_args /* { struct vnode *a_vp; vfs_context_t a_context; } */ *ap;
{
	struct vnode *vp = ap->a_vp;
	void *data = vp->v_data;

	vp->v_data = NULL;
	FREE(data, M_VOLFSNODE);

	return (0);
}

struct volfsgetattr_struct{
	int 	numMounts;
	vnode_t	a_vp;
};

static int
volfs_getattr_callback(mount_t mp, void * arg)
{
	struct volfsgetattr_struct *vstrp = (struct volfsgetattr_struct *)arg;

	if (mp != vnode_mount(vstrp->a_vp) && validfsnode(mp))
		vstrp->numMounts++;
	return(VFS_RETURNED);
}

/*
 * volfs_getattr - fill in the attributes for this vnode
 */
static int
volfs_getattr(ap)
    struct vnop_getattr_args	/* { struct vnode *a_vp; struct vnode_attr *a_vap;
        vfs_context_t a_context; } */ *ap;
{
    struct volfs_vndata *priv_data;
    struct vnode		*a_vp;
    struct vnode_attr	*a_vap;
    int                 numMounts = 0;
    struct volfsgetattr_struct vstr;
    struct timespec ts;

    a_vp = ap->a_vp;
    a_vap = ap->a_vap;

    priv_data = a_vp->v_data;

    VATTR_RETURN(a_vap, va_type, VDIR);
    VATTR_RETURN(a_vap, va_mode, 0555);
    VATTR_RETURN(a_vap, va_nlink, 2);
    VATTR_RETURN(a_vap, va_uid, 0);
    VATTR_RETURN(a_vap, va_gid, 0);
    VATTR_RETURN(a_vap, va_fsid, (int) a_vp->v_mount->mnt_vfsstat.f_fsid.val[0]);
    VATTR_RETURN(a_vap, va_fileid, (uint64_t)((u_long)priv_data->nodeID));
    VATTR_RETURN(a_vap, va_acl, NULL);

    /*
     * If it's the root vnode calculate its size based on the number of eligible
     * file systems
     */
    if (priv_data->vnode_type == VOLFS_ROOT) {
	    vstr.numMounts = 0;
	    vstr.a_vp = a_vp;

	    vfs_iterate(LK_NOWAIT, volfs_getattr_callback, (void *)&vstr);

	    numMounts = vstr.numMounts;

	    VATTR_RETURN(a_vap, va_data_size, (numMounts + 2) * VLFSDIRENTLEN);
    } else {
	    VATTR_RETURN(a_vap, va_data_size, 2 * VLFSDIRENTLEN);
    }

    VATTR_RETURN(a_vap, va_iosize, 512);
    ts.tv_sec = boottime_sec();
    ts.tv_nsec = 0;
    VATTR_RETURN(a_vap, va_access_time, ts);
    VATTR_RETURN(a_vap, va_modify_time, ts);
    VATTR_RETURN(a_vap, va_change_time, ts);

    VATTR_RETURN(a_vap, va_gen, 0);
    VATTR_RETURN(a_vap, va_flags, 0);
    VATTR_RETURN(a_vap, va_rdev, 0);
    VATTR_RETURN(a_vap, va_filerev, 0);

    return (0);
}

/*
 * volfs_select - just say OK.  Only possible op is readdir
 */
static int
volfs_select(__unused struct vnop_select_args *ap)
{
	return (1);
}

/*
 * vofls_rmdir - not possible to remove directories in volfs
 */
static int
volfs_rmdir(ap)
    struct vnop_rmdir_args	/* { struct vnode *a_dvp; struct vnode *a_vp;
        struct componentname *a_cnp; vfs_context_t a_context; } */ *ap;
{
    if (ap->a_dvp == ap->a_vp) {
		(void) nop_rmdir(ap);
		return (EINVAL);
    } else
		return (err_rmdir(ap));
}



static int
volfs_readdir_callback(mount_t mp, void * v)
{
	struct volfs_rdstruct * vcsp = (struct volfs_rdstruct *)v;
	struct dirent       local_dir;
	int error;

            if ((mp != vnode_mount(vcsp->vp)) && validfsnode(mp))
				vcsp->validindex++;

            if (vcsp->rec_offset == vcsp->validindex)
              {
                local_dir.d_fileno = mp->mnt_vfsstat.f_fsid.val[0];
                local_dir.d_type = DT_DIR;
                local_dir.d_reclen = VLFSDIRENTLEN;
                local_dir.d_namlen = sprintf(&local_dir.d_name[0], "%d", mp->mnt_vfsstat.f_fsid.val[0]);
                error = uiomove((char *) &local_dir, VLFSDIRENTLEN, vcsp->uio);
                vcsp->rec_offset++;
              }

		return(VFS_RETURNED);
}

/*
 * volfs_readdir - Get directory entries
 *
 * Directory listings are only produced for the root volfs node.  Filesystems
 * just return . & ..
 * Filesystems contained within the volfs root are named by the decimal
 * equivalent of the f_fsid.val[0] from their mount structure (typically
 * the device id of the volume).  The maximum length for a name, then is
 * 10 characters.
 */
static int
volfs_readdir(ap)
    struct vnop_readdir_args	/* { struct vnode *a_vp; struct uio *a_uio;
				 * int *a_eofflag; int
        *ncookies; u_long **a_cookies; vfs_context_t a_context; } */ *ap;
{
    struct volfs_vndata *priv_data;
    register struct uio *uio = ap->a_uio;
    int                 error = 0;
    size_t              count, lost;
    int                 rec_offset;
    struct dirent       local_dir;
    int                 i;
    int					starting_resid;
    off_t               off;
	struct volfs_rdstruct vcs;
    
	off = uio->uio_offset;
    priv_data = ap->a_vp->v_data;
	// LP64todo - fix this!
    starting_resid = count = uio_resid(uio);
 
    /* Make sure we don't return partial entries. */
    count -= (uio->uio_offset + count) & (VLFSDIRENTLEN - 1);
	if (count <= 0) {
		return (EINVAL);
	}
    /*
     * Make sure we're starting on a directory boundary
     */
	if (off & (VLFSDIRENTLEN - 1)) {
		return (EINVAL);
	}
    rec_offset = off / VLFSDIRENTLEN;
	// LP64todo - fix this!
    lost = uio_resid(uio) - count;
    uio_setresid(uio, count);
    uio_iov_len_set(uio, count); 
#if LP64_DEBUG
	if (IS_VALID_UIO_SEGFLG(uio->uio_segflg) == 0) {
		panic("%s :%d - invalid uio_segflg\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

    local_dir.d_reclen = VLFSDIRENTLEN;
    /*
     * We must synthesize . and ..
     */

    if (rec_offset == 0)
      {
        /*
         * Synthesize .
         */
        local_dir.d_fileno = priv_data->nodeID;
        local_dir.d_type = DT_DIR;
        local_dir.d_namlen = 1;
        local_dir.d_name[0] = '.';
        for (i = 1; i < MAXVLFSNAMLEN; i++)
            local_dir.d_name[i] = 0;
        error = uiomove((char *) &local_dir, VLFSDIRENTLEN, uio);
        rec_offset++;
      }
    if (rec_offset == 1)
      {
        /*
         * Synthesize ..
         * We only have two levels in the volfs hierarchy.  Root's
         * .. points to itself and the second level points to root,
         * hence we've hardcoded d_fileno for .. here
         */
        local_dir.d_fileno = ROOT_DIRID;
        local_dir.d_type = DT_DIR;
        local_dir.d_namlen = 2;
        local_dir.d_name[0] = '.';
        local_dir.d_name[1] = '.';
        for (i = 2; i < MAXVLFSNAMLEN; i++)
            local_dir.d_name[i] = 0;
        error = uiomove((char *) &local_dir, VLFSDIRENTLEN, uio);
        rec_offset++;
      }

    /*
     * OK, we've given them the . & .. entries.  If this is a
     * filesystem node then we've gone as far as we're going
     * to go
     */
    if (priv_data->vnode_type == VOLFS_FSNODE)
        {
        *ap->a_eofflag = 1;	/* we got all the way to the end */
        return (error);
        }

    if (rec_offset > 1) {
		vcs.validindex = 1;		/* we always have "." and ".." */
		vcs.rec_offset = rec_offset;
		vcs.vp = ap->a_vp;
		vcs.uio = uio;
		
	
		vfs_iterate(0, volfs_readdir_callback, &vcs);

        //if (mp == (void *) &mountlist)
            *ap->a_eofflag = 1;	/* we got all the way to the end */
    }
    uio_setresid(uio, (uio_resid(uio) + lost));

    if (starting_resid == uio_resid(uio))
        uio->uio_offset = 0;

    return (error);
}


/*
 * validfsnode - test to see if a file system supports VGET
 *
 * This can cause context switching, so caller should be lock safe
 */
int
validfsnode(struct mount *fsnode)
{

	/*
	 * Just check to see if the the mount flag is set, if it is we assume the
	 * file system supports all of volfs symantecs
	 */

    if ((! (fsnode->mnt_kern_flag & MNTK_UNMOUNT)) && (fsnode->mnt_flag & MNT_DOVOLFS))
		return 1;
	else 
		return 0;
}

/*
 * volfs_pathconf - Return POSIX pathconf information applicable to ufs filesystems.
 */
static int
volfs_pathconf(ap)
    struct vnop_pathconf_args	/* { struct vnode *a_vp; int a_name; int
        *a_retval; vfs_context_t a_context; } */ *ap;
{
    switch (ap->a_name)
      {
        case _PC_LINK_MAX:
            *ap->a_retval = LINK_MAX;
            return (0);
        case _PC_NAME_MAX:
            *ap->a_retval = NAME_MAX;
            return (0);
        case _PC_PATH_MAX:
            *ap->a_retval = PATH_MAX;
            return (0);
        case _PC_PIPE_BUF:
            *ap->a_retval = PIPE_BUF;
            return (0);
        case _PC_CHOWN_RESTRICTED:
            *ap->a_retval = 1;
            return (0);
        case _PC_NO_TRUNC:
            *ap->a_retval = 1;
            return (0);
        default:
            return (EINVAL);
      }
    /* NOTREACHED */
}

/* 
 * get_parentvp() - internal routine that tries to lookup the parent of vpp.
 * On success, *vpp is the parent vp and is returned with a reference. 
 */
static int
get_parentvp(struct vnode **vpp, struct mount *mp, vfs_context_t context)
{
	int result;
	struct vnode_attr va;
	struct vnode *child_vp = *vpp;
	
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_parentid);
	result = vnode_getattr(child_vp, &va, context);
	if (result) {
		return result;
	}

	/* Shift attention to the parent directory vnode: */
	result = VFS_VGET(mp, (ino64_t)va.va_parentid, vpp, context);

	if (result == 0 && child_vp->v_parent != *vpp) {
	        vnode_update_identity(child_vp, *vpp, NULL, 0, 0, VNODE_UPDATE_PARENT);
	}

	return result;
}	


/*
 * Look up the parent directory of a given vnode.
 */
static int
lookup_parent(vnode_t child_vp, vnode_t *parent_vpp, int is_authorized, vfs_context_t context)
{
	struct componentname cn;
	vnode_t new_vp;
	int error;

	*parent_vpp = NULLVP;

	if (is_authorized == 0) {
		error = vnode_authorize(child_vp, NULL, KAUTH_VNODE_SEARCH, context);
		if (error != 0) {
			return (error);
		}
	}
	new_vp = child_vp->v_parent;

	if (new_vp != NULLVP) {
	        if ( (error = vnode_getwithref(new_vp)) == 0 )
		        *parent_vpp = new_vp;
		return (error);
	}
	bzero(&cn, sizeof(cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_context = context;
	cn.cn_pnbuf = CAST_DOWN(caddr_t, &gDotDot);
	cn.cn_pnlen = strlen(cn.cn_pnbuf);
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = cn.cn_pnlen;
	cn.cn_flags = (FOLLOW | LOCKLEAF | ISLASTCN | ISDOTDOT);

	error = VNOP_LOOKUP(child_vp, &new_vp, &cn, context);
	if (error != 0) {
		return(error);
	}
	if (new_vp == child_vp) {
		vnode_put(new_vp);
		return ELOOP;
	}
	if (child_vp->v_parent == NULLVP) {
	        vnode_update_identity(child_vp, new_vp, NULL, 0, 0, VNODE_UPDATE_PARENT);
	}
	*parent_vpp = new_vp;
	return 0;
}


/*
 * 	verify_fullpathaccess(ret_vnode);
 */

static int
verify_fullpathaccess(struct vnode *targetvp, vfs_context_t context)
{
	struct vnode *vp, *parent_vp;
	struct mount *mp = targetvp->v_mount;
	struct proc *p = vfs_context_proc(context);
	int result;
	int dp_authorized;
	struct filedesc *fdp = p->p_fd;	/* pointer to file descriptor state */
	
	vp = targetvp;
	dp_authorized = 0;
	
	/* get the parent directory. */
	if ((vp->v_flag & VROOT) == 0 && vp != fdp->fd_cdir && vp != fdp->fd_rdir) {
		if (vp->v_parent == NULLVP || (vp->v_flag & VISHARDLINK) || (vnode_getwithref(vp->v_parent) != 0)) {
			if (vp->v_type == VDIR) {
				result = lookup_parent(vp, &parent_vp, dp_authorized, context);
	
				/*
				 * If the lookup fails with EACCES and the vp is a directory,
				 * we should try again but bypass authorization check. Without this
				 * workaround directories that you can navigate to but not traverse will 
				 * disappear when clicked in the Finder.
				 */
				if (result == EACCES && (vp->v_flag & VROOT) == 0) {
					dp_authorized = 1;  /* bypass auth check */
					if (lookup_parent(vp, &parent_vp, dp_authorized, context) == 0) {
						result = 0;
					}
					dp_authorized = 0; /* force us to authorize */
				}
				vp = parent_vp;
			}
			else {
				/*
				 * this is not a directory so we must get parent object ID
				 */
				result = get_parentvp(&vp, mp, context);
				parent_vp = vp;
			}
			if (result != 0) 
				goto err_exit;
		}
		else {
			/*
			 * we where able to get a reference on v_parent
			 */
			parent_vp = vp = vp->v_parent;
		}
	} 

	/*
	 * Keep going up until either the process's root or the process's working 
	 * directory is hit, either one of which are potential valid starting points 
	 * for a full pathname
	 */
	while (vp != NULLVP) {

		result = reverse_lookup(vp, &parent_vp, fdp, context, &dp_authorized);
		if (result == 0) {
			/*
			 * we're done and we have access
			 */
			break;
		}
		if (vp != parent_vp) {
		        /*
			 * we where able to walk up the parent chain so now we don't need
			 * vp any longer
			 */
			vnode_put(vp);	
			vp = parent_vp;
		}
		/*
		 * we have a referenced vp at this point... if dp_authorized == 1, than
		 * it's been authorized for search, but v_parent was NULL...
		 * if dp_authorized == 0, than we need to do the authorization check
		 * before looking up the parent
		 */
		if ((vp->v_flag & VROOT) != 0 ||
		    vp == fdp->fd_cdir || vp == fdp->fd_rdir) {
		        /*
			 * we're already at the termination point, which implies that
			 * the authorization check in the cache failed (otherwise we
			 * would have returned 'done' from "reverse_lookup"... so,
			 * do the authorization and bail
			 */
			result = vnode_authorize(vp, NULL, KAUTH_VNODE_SEARCH, context);
			goto lookup_exit;
		}
		result = lookup_parent(vp, &parent_vp, dp_authorized, context);
		if (result != 0) {
			goto lookup_exit;
		}
		if (vp != parent_vp) {
		        /*
			 * got the parent so now we don't need vp any longer
			 */
			vnode_put(vp);	
			vp = parent_vp;
		}
	} /* while loop */

	/*
	 * Success: the caller has complete access to the initial vnode
	 */
	result = 0; 

lookup_exit:
	if (vp != NULLVP && vp != targetvp) {
		vnode_put(vp);
	}
		
err_exit:
	return result;
};


/*
 * get_fsvnode - internal routine to create a vnode for a file system.  Called with mount pointer,
 *   id of filesystem to lookup and pointer to vnode pointer to fill in
 */
static int
get_fsvnode(struct mount *our_mount, int id, vnode_t *ret_vnode)
{
    struct mount       *cur_mount;
	fsid_t				cur_fsid;
    struct vnode       *cur_vnode;
    struct volfs_vndata *cur_privdata;
	int					retval;
	struct vnode_fsparam vfsp;
	int	vid = 0;

    /*
     * OK, first look up the matching mount on the list of mounted file systems
     */
	/* the following will return the mount point with vfs_busy held */
	cur_mount = mount_lookupby_volfsid(id, 1);

    if (cur_mount == NULL) {
        /*
         * No mounted file system by the specified ID currently exists in the system.
         *
         * XXX We could deal with a vnode that is still hanging about for an FS that
         * does not exists or has been unmounted now, or count on the update below
         * to happen later...
         */
        *ret_vnode = NULL;
        return ENOENT;
    };

	cur_fsid = cur_mount->mnt_vfsstat.f_fsid;

    /*
     * Now search the list attached to the mount structure to
     * see if this vnode is already floating around
     */
search_vnodelist:
	mount_lock(our_mount);
	TAILQ_FOREACH(cur_vnode, &our_mount->mnt_vnodelist, v_mntvnodes)  {
        cur_privdata = (struct volfs_vndata *) cur_vnode->v_data;
        if (cur_privdata->nodeID == (unsigned int)id)
            {
            if (cur_privdata->fs_mount != cur_mount) {
                cur_privdata->fs_mount = cur_mount;
                cur_privdata->fs_fsid = cur_fsid;
            };
            break;
            }
	}
	mount_unlock(our_mount);

    if (cur_vnode) {
        vid = vnode_vid(cur_vnode);

        /*
	 * use vnode_getwithvid since it will wait for a vnode currently being
	 * terminated... if it returns an error, cur_vnode will not be what we
	 * think it is, try again
	 */
        if (vnode_getwithvid(cur_vnode, vid) != 0) {
            goto search_vnodelist;
        };
        }
    else
      {
        MALLOC(cur_privdata, struct volfs_vndata *,
               sizeof(struct volfs_vndata), M_VOLFSNODE, M_WAITOK);

        cur_privdata->vnode_type = VOLFS_FSNODE;
        cur_privdata->nodeID = id;

        cur_privdata->fs_mount = cur_mount;
        cur_privdata->fs_fsid = cur_fsid;

		vfsp.vnfs_mp = our_mount;
		vfsp.vnfs_vtype = VDIR;
		vfsp.vnfs_str = "volfs";
		vfsp.vnfs_dvp = 0;
		vfsp.vnfs_fsnode = cur_privdata;
		vfsp.vnfs_cnp = 0;
		vfsp.vnfs_vops = volfs_vnodeop_p;
		vfsp.vnfs_rdev = 0;
		vfsp.vnfs_filesize = 0;
		vfsp.vnfs_flags = VNFS_NOCACHE | VNFS_CANTCACHE;
		vfsp.vnfs_marksystem = 0;
		vfsp.vnfs_markroot = 0;

		retval = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &cur_vnode);
        if (retval != 0) {
            FREE(cur_privdata, M_VOLFSNODE);
			goto out;
        };
		cur_vnode->v_tag = VT_VOLFS;
			
      }

    *ret_vnode = cur_vnode;
	retval = 0;
out:
	vfs_unbusy(cur_mount);
    return (retval);
}



/*
 * get_filevnode - returns the vnode for the given id within a filesystem.  The parent vnode
 * 	   is a filesystem, id is the 32-bit id of the file/directory and ret_vnode is a pointer
 *		to a vnode pointer
 */
static int
get_filevnode(struct mount *parent_fs, u_int id, vnode_t *ret_vnode, vfs_context_t context)
{
    int                 retval;

again:
	/*
	 * Special case 2 to mean the root of a file system
	 */
	if (id == 2)
		retval = VFS_ROOT(parent_fs, ret_vnode, context);
	else
		retval = VFS_VGET(parent_fs, (ino64_t)id, ret_vnode, context);
	if (retval) goto error;

	retval = verify_fullpathaccess(*ret_vnode, context);
	if (retval) {
		/* An error was encountered verifying that the caller has,
		   in fact, got access all the way from "/" or their working
		   directory to the specified item...
		 */
		vnode_put(*ret_vnode);
		*ret_vnode = NULL;
		/* vnode was recycled during access verification. */
		if (retval == EAGAIN) {
			goto again;
		}
	};

error:
    return (retval);
}


static int
volfs_lookup(struct vnop_lookup_args *ap)
{
	struct volfs_vndata *priv_data;
	char  *nameptr;
	long  namelen;
	struct mount  *parent_fs;
	vnode_t	vp;
	int  isdot_or_dotdot = 0;
	int  ret_err = ENOENT;
	char firstchar;
	int ret_val;

#if 0
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSVN, 8)) | DBG_FUNC_START,
		     (unsigned int)ap->a_dvp, (unsigned int)ap->a_cnp, (unsigned int)p, 0, 0);
#endif
	priv_data = ap->a_dvp->v_data;
	nameptr = ap->a_cnp->cn_nameptr;
	namelen = ap->a_cnp->cn_namelen;
	firstchar = nameptr[0];

	/* First check for "." and ".." */
	if (firstchar == '.') {
		if (namelen == 1) {
			/* "." requested */
			isdot_or_dotdot = 1;
			*ap->a_vpp = ap->a_dvp;
			vnode_get(*ap->a_vpp);
			ret_err = 0;
		} else if (nameptr[1] == '.' && namelen == 2) {
			/* ".." requested */
			isdot_or_dotdot = 1;
			ret_err = VFS_ROOT(ap->a_dvp->v_mount, ap->a_vpp, ap->a_context);
		}
	} else if (firstchar == '@') { /* '@' is alias for system root */
		if ((namelen == 1) && (priv_data->vnode_type != VOLFS_ROOT)) {
			/* the following returns with iteration count on mount point */
			parent_fs = mount_list_lookupby_fsid(&priv_data->fs_fsid, 0, 1);
			if (parent_fs) {
				ret_val = vfs_busy(parent_fs, LK_NOWAIT);
				mount_iterdrop(parent_fs);
				if (ret_val !=0) {
					*ap->a_vpp = NULL;
					ret_err = ENOENT;
				} else {
					ret_err = VFS_ROOT(parent_fs, ap->a_vpp, ap->a_context);
					vfs_unbusy(parent_fs);
				}
			} else {
				*ap->a_vpp = NULL;
				ret_err = ENOENT;
			}
		} else {
			*ap->a_vpp = NULL;
			ret_err = ENOENT;
		}
	} else if (namelen <= 10 && firstchar > '0' && firstchar <= '9') {
		char	*check_ptr;
		u_long	id;

		id = strtoul(nameptr, &check_ptr, 10);

		/*
		 * strtol will leave us at the first non-numeric character.
		 * we've checked to make sure the component name does
		 * begin with a numeric so check_ptr must wind up on
		 * the terminating null or there was other junk following the
		 * number
		 */
		if ((check_ptr - nameptr) == namelen) {
			if (priv_data->vnode_type == VOLFS_ROOT) {
				/*
				 * OPTIMIZATION
				 *
				 * Obtain the mountpoint and call VFS_VGET in
				 * one step (ie without creating a vnode for
				 * the mountpoint).
				 */
				if (check_ptr[0] == '/' &&
				    check_ptr[1] > '0' && check_ptr[1] <= '9') {
					struct mount *mp;
					struct vnode *vp;
					u_long	id2;
					char *endptr;
		
					/* this call will return mount point with vfs_busy held */
					mp = mount_lookupby_volfsid(id, 1);
					if (mp == NULL) {
						*ap->a_vpp = NULL;
						return ENOENT;
					}
					id2 = strtoul(&check_ptr[1], &endptr, 10);
					if ((endptr[0] == '/' || endptr[0] == '\0') &&
					    get_filevnode(mp, id2, &vp, ap->a_context) == 0) {
						ap->a_cnp->cn_consume = endptr - check_ptr;
						*ap->a_vpp = vp;
						vfs_unbusy(mp);
						return (0);
					}
					vfs_unbusy(mp);
				}
				/* Fall through to default behavior... */

				ret_err = get_fsvnode(ap->a_dvp->v_mount, id, ap->a_vpp);

			} else {
				parent_fs = mount_list_lookupby_fsid(&priv_data->fs_fsid, 0, 1);
				if (parent_fs) {
					ret_val = vfs_busy(parent_fs, LK_NOWAIT);
					mount_iterdrop(parent_fs);
					if (ret_val !=0) {
						*ap->a_vpp = NULL;
						ret_err = ENOENT;
					} else {
						ret_err = get_filevnode(parent_fs, id, ap->a_vpp, ap->a_context);
						vfs_unbusy(parent_fs);
					}
				} else {
						*ap->a_vpp = NULL;
						ret_err = ENOENT;
				}
			}
		}
	}
	vp = *ap->a_vpp;

	if ( ret_err == 0 && !isdot_or_dotdot && (vp != NULLVP) && (vp->v_parent == NULLVP))
	        vnode_update_identity(vp, ap->a_dvp, NULL, 0, 0, VNODE_UPDATE_PARENT);

#if 0
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSVN, 8)) | DBG_FUNC_START,
		     (unsigned int)ap->a_dvp, (unsigned int)ap->a_cnp, (unsigned int)p, ret_err, 0);
#endif
	return (ret_err);
}

