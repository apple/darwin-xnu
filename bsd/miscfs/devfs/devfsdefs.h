/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
 * devfsdefs.h
 */

/*
 * HISTORY
 *  8-April-1999 Dieter Siegmund (dieter@apple.com)
 *	Ported to from FreeBSD 3.1
 *	Removed unnecessary/unused defines
 *	Renamed structures/elements to clarify usage in code.
 */

#ifndef __DEVFS_DEVFSDEFS_H__
#define __DEVFS_DEVFSDEFS_H__

#include  <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
#define DEVMAXNAMESIZE 	32 		/* XXX */
#define DEVMAXPATHSIZE 	128		/* XXX */

typedef enum {
    DEV_DIR,
    DEV_BDEV,
    DEV_CDEV,
    DEV_SLNK,
} devfstype_t;

extern int (**devfs_vnodeop_p)(void *);	/* our own vector array for dirs */
extern int (**devfs_spec_vnodeop_p)(void *); /* our own vector array for devs */
extern struct vfsops devfs_vfsops;

typedef	struct devnode		devnode_t;
typedef struct devdirent 	devdirent_t;
typedef union devnode_type 	devnode_type_t;

struct devfs_stats {
    int			nodes;
    int			entries;
    int			mounts;
    int			stringspace;
};

union devnode_type {
    dev_t		dev;
    struct {
	devdirent_t *	dirlist;
	devdirent_t * *	dirlast;
	devnode_t *	parent;
	devdirent_t *	myname;		/* my entry in .. */
	int		entrycount;
    }Dir;
    struct {
	char *		name;	/* must be allocated separately */
	int		namelen;
    }Slnk;
};

#define	DN_ACCESS	0x0001		/* Access time update request. */
#define	DN_CHANGE	0x0002		/* Inode change time update request. */
#define	DN_UPDATE	0x0004		/* Modification time update request. */
#define	DN_MODIFIED	0x0008		/* Inode has been modified. */
#define	DN_RENAME	0x0010		/* Inode is being renamed. */

struct devnode
{
    devfstype_t		dn_type;
    int			dn_flags;
    u_short		dn_mode;
    uid_t		dn_uid; 
    gid_t		dn_gid;
    struct timespec	dn_atime;/* time of last access */
    struct timespec	dn_mtime;/* time of last modification */
    struct timespec	dn_ctime;/* time file changed */
    int	(***dn_ops)(void *);/* yuk... pointer to pointer(s) to funcs */
    int			dn_links;/* how many file links does this node have? */
    struct devfsmount *	dn_dvm; /* the mount structure for this 'plane' */
    struct vnode *	dn_vn;	/* address of last vnode that represented us */
    int			dn_len;   /* of any associated info (e.g. dir data) */
    devdirent_t *	dn_linklist;/* circular list of hardlinks to this node */
    devdirent_t *	dn_last_lookup;	/* name I was last looked up from */
    devnode_t *		dn_nextsibling;	/* the list of equivalent nodes */
    devnode_t * *	dn_prevsiblingp;/* backpointer for the above */
    devnode_type_t	dn_typeinfo;
    int			dn_delete;	/* mark for deletion */
};

struct devdirent
{
    /*-----------------------directory entry fields-------------*/
    char		de_name[DEVMAXNAMESIZE];
    devnode_t *		de_dnp;		/* the "inode" (devnode) pointer */
    devnode_t *		de_parent;	/* backpointer to the directory itself */
    devdirent_t *	de_next;	/* next object in this directory */
    devdirent_t *	*de_prevp;	/* previous pointer in directory linked list */
    devdirent_t *	de_nextlink;	/* next hardlink to this node */
    devdirent_t *	*de_prevlinkp;	/* previous hardlink pointer for this node */
};

extern devdirent_t * 		dev_root;
extern struct lock__bsd__	devfs_lock;
extern struct devfs_stats	devfs_stats;

/*
 * Rules for front nodes:
 * Dirs hava a strict 1:1 relationship with their OWN devnode
 * Symlinks similarly
 * Device Nodes ALWAYS point to the devnode that is linked
 * to the Backing node. (with a ref count)
 */

/*
 * DEVFS specific per/mount information, used to link a monted fs to a
 * particular 'plane' of front nodes.
 */
struct devfsmount
{
    struct mount *	mount;	/* vfs mount struct for this fs	*/
    devdirent_t *	plane_root;/* the root of this 'plane'	*/
};

/*
 * Prototypes for DEVFS virtual filesystem operations
 */
#include <sys/lock.h>
#include <miscfs/devfs/devfs_proto.h>

//#define HIDDEN_MOUNTPOINT	1

/* misc */
#define M_DEVFSNAME	M_DEVFS
#define M_DEVFSNODE	M_DEVFS
#define M_DEVFSMNT	M_DEVFS

static __inline__ void
getnanotime(struct timespec * t_p)
{
    struct timeval tv;

    microtime(&tv);
    t_p->tv_sec = tv.tv_sec;
    t_p->tv_nsec = tv.tv_usec * 1000;
    return;
}

#define VTODN(vp)	((devnode_t *)(vp)->v_data)
extern void cache_purge(struct vnode *vp); /* vfs_cache.c */

static __inline__ int
DEVFS_LOCK(struct proc * p)
{
    return (lockmgr(&devfs_lock, LK_EXCLUSIVE, NULL, p));
}

static __inline__ int
DEVFS_UNLOCK(struct proc * p)
{
    return (lockmgr(&devfs_lock, LK_RELEASE, NULL, p));
}

static __inline__ void
DEVFS_INCR_ENTRIES()
{
    devfs_stats.entries++;
}

static __inline__ void
DEVFS_DECR_ENTRIES()
{
    devfs_stats.entries--;
}

static __inline__ void
DEVFS_INCR_NODES()
{
    devfs_stats.nodes++;
}

static __inline__ void
DEVFS_DECR_NODES()
{
    devfs_stats.nodes--;
}

static __inline__ void
DEVFS_INCR_MOUNTS()
{
    devfs_stats.mounts++;
}

static __inline__ void
DEVFS_DECR_MOUNTS()
{
    devfs_stats.mounts--;
}

static __inline__ void
DEVFS_INCR_STRINGSPACE(int space)
{
    devfs_stats.stringspace += space;
}

static __inline__ void
DEVFS_DECR_STRINGSPACE(int space)
{
    devfs_stats.stringspace -= space;
    if (devfs_stats.stringspace < 0) {
	printf("DEVFS_DECR_STRINGSPACE: (%d - %d < 0)\n",
	       devfs_stats.stringspace + space, space);
	devfs_stats.stringspace = 0;
    }
}

static __inline__ void
dn_times(devnode_t * dnp, struct timeval t1, struct timeval t2) 
{
    if (dnp->dn_flags & (DN_ACCESS | DN_CHANGE | DN_UPDATE)) {
	if (dnp->dn_flags & DN_ACCESS) {
	    dnp->dn_atime.tv_sec = t1.tv_sec;
	    dnp->dn_atime.tv_nsec = t1.tv_usec * 1000;
	}
	if (dnp->dn_flags & DN_UPDATE) {
	    dnp->dn_mtime.tv_sec = t2.tv_sec;
	    dnp->dn_mtime.tv_nsec = t2.tv_usec * 1000;
	}
	if (dnp->dn_flags & DN_CHANGE) {
	    dnp->dn_ctime.tv_sec = time.tv_sec;
	    dnp->dn_ctime.tv_nsec = time.tv_usec * 1000;
	}
	dnp->dn_flags &= ~(DN_ACCESS | DN_CHANGE | DN_UPDATE);
    }
    return;
}

static __inline__ void
dn_copy_times(devnode_t * target, devnode_t * source)
{
    target->dn_atime = source->dn_atime;
    target->dn_mtime = source->dn_mtime;
    target->dn_ctime = source->dn_ctime;
    return;
}
#endif /* __APPLE_API_PRIVATE */
#endif /* __DEVFS_DEVFSDEFS_H__ */
