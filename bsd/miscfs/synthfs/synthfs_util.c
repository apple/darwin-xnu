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
/* Copyright (c) 1998, Apple Computer, Inc. All rights reserved. */
/*
 * Change History:
 *
 *	17-Aug-1999	Pat Dirks	New today.
 *
 */

#include <mach/mach_types.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/namei.h>
#include <sys/attr.h>
#include <sys/time.h>

#include <sys/vm.h>
#include <sys/errno.h>
#include <vfs/vfs_support.h>

#include "synthfs.h"

struct synthfs_direntry_head {
	u_int32_t d_fileno;		/* file number of entry */
	u_int16_t d_reclen;		/* length of this record */
	u_int8_t  d_type; 		/* file type, see below */
	u_int8_t  d_namlen;		/* length of string in d_name */
};


#define PATHSEPARATOR '/'
#define ROOTDIRID 2

void synthfs_setupuio(struct iovec *iov,
					  struct uio *uio,
					  void *buffer,
					  size_t bufsize,
					  enum uio_seg space,
					  enum uio_rw direction,
					  struct proc *p) {
	iov->iov_base = (char *)buffer;
	iov->iov_len = bufsize;
	
	uio->uio_iov = iov;
	uio->uio_iovcnt = 1;
	uio->uio_offset = 0;
	uio->uio_resid = bufsize;
	uio->uio_segflg = space;
	uio->uio_rw = direction;
	uio->uio_procp = p;
}


static int synthfs_insertnode(struct synthfsnode *newnode_sp, struct synthfsnode *parent_sp) {
	struct timeval now;
	
	DBG_ASSERT(parent_sp->s_type == SYNTHFS_DIRECTORY);
	
    TAILQ_INSERT_TAIL(&parent_sp->s_u.d.d_subnodes, newnode_sp, s_sibling);
	++parent_sp->s_u.d.d_entrycount;
	newnode_sp->s_parent = parent_sp;
	
    parent_sp->s_nodeflags |= IN_CHANGE | IN_MODIFIED;
    now = time;
	VOP_UPDATE(STOV(parent_sp), &now, &now, 0);
	
	return 0;
}



static int synthfs_newnode(struct mount *mp, struct vnode *dp, const char *name, unsigned long nodeid, mode_t mode, struct proc *p, struct vnode **vpp) {
	int result;
    struct synthfsnode *sp;
	struct vnode *vp;
    struct timeval now;
    char *nodename;

    /* Allocate the synthfsnode now to avoid blocking between the call
       to getnewvnode(), below, and the initialization of v_data: */
    MALLOC(sp, struct synthfsnode *, sizeof(struct synthfsnode), M_SYNTHFS, M_WAITOK);
    
    if (name == NULL) {
        MALLOC(nodename, char *, 1, M_TEMP, M_WAITOK);
        nodename[0] = 0;
    } else {
        MALLOC(nodename, char *, strlen(name) + 1, M_TEMP, M_WAITOK);
        strcpy(nodename, name);
    };

	/*
	   Note that getnewvnode() returns the vnode with a refcount of +1;
	   this routine returns the newly created vnode with this positive refcount.
	 */	
    result = getnewvnode(VT_SYNTHFS, mp, synthfs_vnodeop_p, &vp);
    if (result != 0) {
        DBG_VOP(("getnewvnode failed with error code %d\n", result));
	FREE(nodename, M_TEMP);
        FREE(sp, M_TEMP);
        return result;
    }
    if (vp == NULL) {
        DBG_VOP(("getnewvnod returned NULL without an error!\n"));
	FREE(nodename, M_TEMP);
        FREE(sp, M_TEMP);
        return EINVAL;
    }

    /* Initialize the relevant synthfsnode fields: */
    bzero(sp, sizeof(*sp));
    lockinit(&sp->s_lock, PINOD, "synthfsnode", 0, 0);
    sp->s_nodeid = nodeid;
    
    /* Initialize all times from a consistent snapshot of the clock: */
    now = time;
    sp->s_createtime = now;
    sp->s_accesstime = now;
    sp->s_modificationtime = now;
    sp->s_changetime = now;
    sp->s_name = nodename;
    sp->s_mode = mode;

    sp->s_vp = vp;
    vp->v_data = sp;

    vget(vp, LK_EXCLUSIVE, p);
    
    /* If there's a parent directory, update its subnode structures to insert this new node: */
    if (dp) {
    	result = synthfs_insertnode(sp, VTOS(dp));
    };

    *vpp = vp;

    return result;
}


    
int synthfs_remove_entry(struct vnode *vp) {
	struct synthfsnode *sp = VTOS(vp);
	struct synthfsnode *psp = sp->s_parent;
	struct timeval now;
	
	if (psp) {
		TAILQ_REMOVE(&psp->s_u.d.d_subnodes, sp, s_sibling);
		--psp->s_u.d.d_entrycount;
		
		psp->s_nodeflags |= IN_CHANGE | IN_MODIFIED;
		now = time;
		VOP_UPDATE(STOV(psp), &now, &now, 0);
	};
	
    return 0;
}



int synthfs_move_rename_entry(struct vnode *source_vp, struct vnode *newparent_vp, char *new_name) {
	struct synthfsnode *source_sp = VTOS(source_vp);
	struct synthfsnode *parent_sp = VTOS(newparent_vp);
	char *new_name_ptr;
	int result = 0;
	
	/* Unlink the entry from its current place: */
	result = synthfs_remove_entry(source_vp);
	if (result) goto err_exit;

	/* Change the name as necessary: */
	if (new_name) {
		FREE(source_sp->s_name, M_TEMP);
		MALLOC(new_name_ptr, char *, strlen(new_name) + 1, M_TEMP, M_WAITOK);
		strcpy(new_name_ptr, new_name);
		source_sp->s_name = new_name_ptr;
	};
	
	/* Insert the entry in its new home: */
	result = synthfs_insertnode(source_sp, parent_sp);

err_exit:
	return result;
}



int synthfs_new_directory(struct mount *mp, struct vnode *dp, const char *name, unsigned long nodeid, mode_t mode, struct proc *p, struct vnode **vpp) {
	int result;
	struct vnode *vp;
    struct synthfsnode *sp;
	
	result = synthfs_newnode(mp, dp, name, nodeid, mode, p, &vp);
	if (result) {
		return result;
	};
    sp = VTOS(vp);
    sp->s_linkcount = 2;
	
    /* Initialize the relevant vnode fields: */
    vp->v_type = VDIR;
    if (dp) {
    	++VTOS(dp)->s_linkcount;					/* Account for the [fictitious] ".." link */
    };
    
    /* Set up the directory-specific fields: */
    sp->s_type = SYNTHFS_DIRECTORY;
    sp->s_u.d.d_entrycount = 0;						/* No entries in this directory yet */
    TAILQ_INIT(&sp->s_u.d.d_subnodes);				/* No subnodes of this directory yet */

    *vpp = vp;
    
    return 0;
}



int synthfs_remove_directory(struct vnode *vp) {
	struct synthfsnode *sp = VTOS(vp);
	struct synthfsnode *psp = sp->s_parent;

	if (psp && (sp->s_type == SYNTHFS_DIRECTORY) && (psp != sp)) {
		--psp->s_linkcount;					/* account for the [fictitious] ".." link now removed */
	};

	/* Do the standard cleanup involved in pruning an entry from the filesystem: */
	return synthfs_remove_entry(vp);			/* Do whatever standard cleanup is required */
}



int synthfs_new_symlink(
		struct mount *mp,
		struct vnode *dp,
		const char *name,
		unsigned long nodeid,
		char *targetstring,
		struct proc *p,
		struct vnode **vpp) {
	
	int result;
	struct vnode *vp;
	struct synthfsnode *sp;
	
	result = synthfs_newnode(mp, dp, name, nodeid, 0, p, &vp);
	if (result) {
		return result;
	};
    sp = VTOS(vp);
    sp->s_linkcount = 1;
	
    /* Initialize the relevant vnode fields: */
    vp->v_type = VLNK;
    
    /* Set up the symlink-specific fields: */
    sp->s_type = SYNTHFS_SYMLINK;
    sp->s_u.s.s_length = strlen(targetstring);
    MALLOC(sp->s_u.s.s_symlinktarget, char *, sp->s_u.s.s_length + 1, M_TEMP, M_WAITOK);
    strcpy(sp->s_u.s.s_symlinktarget, targetstring);
    
    *vpp = vp;
    
    return 0;
}



int synthfs_remove_symlink(struct vnode *vp) {
	struct synthfsnode *sp = VTOS(vp);
	
	FREE(sp->s_u.s.s_symlinktarget, M_TEMP);

	/* Do the standard cleanup involved in pruning an entry from the filesystem: */
	return synthfs_remove_entry(vp);					/* Do whatever standard cleanup is required */
}






long synthfs_adddirentry(u_int32_t fileno, u_int8_t type, const char *name, struct uio *uio) {
    struct synthfs_direntry_head direntry;
	long namelength;
    int padding;
    long padtext = 0;
    unsigned short direntrylength;

    namelength = ((name == NULL) ? 0 : strlen(name) + 1);
    padding = (4 - (namelength & 3)) & 3;
    direntrylength = sizeof(struct synthfs_direntry_head) + namelength + padding;

	direntry.d_fileno = fileno;
    direntry.d_reclen = direntrylength;
	direntry.d_type = type;
	direntry.d_namlen = namelength;

    if (uio->uio_resid < direntry.d_reclen) {
        direntrylength = 0;
    } else {
        uiomove((caddr_t)(&direntry), sizeof(direntry), uio);
        if (name != NULL) {
            uiomove((caddr_t)name, namelength, uio);
        };
        if (padding > 0) {
            uiomove((caddr_t)&padtext, padding, uio);
        };
    };

    return direntrylength;
}


