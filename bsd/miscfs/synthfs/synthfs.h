/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1998, Apple Computer, Inc. All rights reserved. */
/*
 * Header file for synthfs data structures
 *
 * Change History:
 *
 *	17-Aug-1999	Pat Dirks	New today.
 *
 */

#ifndef __SYNTHFS_H__
#define __SYNTHFS_H__

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/queue.h>
#include <sys/attr.h>


#if DEBUG
extern void Debugger(const char *message);		/* Private to pexpert... */
#endif
__END_DECLS

/* XXX Get rid of this as soon as sys/malloc.h can be updated to define a real M_SYNTHFS */
#define M_SYNTHFS M_TEMP

/* XXX Get rid of this as soon as sys/vnode.h can be updated to define a real VT_SYNTHFS */
#define VT_SYNTHFS (VT_OTHER+1)


struct synthfs_mntdata
{
	struct mount *synthfs_mp;				/* filesystem vfs structure */
	struct vnode *synthfs_rootvp;
	dev_t synthfs_mounteddev;
	unsigned long synthfs_nextid;
	unsigned long synthfs_filecount;
	unsigned long synthfs_dircount;
	unsigned long synthfs_encodingsused;
	LIST_HEAD(synthfs_fsvnodelist, vnode) synthfs_fsvnodes;
};

/*
 * Various sorts of synthfs vnodes:
 */
enum synthfsnodetype {
    SYNTHFS_DIRECTORY = 1,
    SYNTHFS_FILE,
    SYNTHFS_SYMLINK
};

struct synthfs_dir_node {
	unsigned long d_entrycount;
	TAILQ_HEAD(synthfs_d_subnodelist, synthfsnode) d_subnodes;
	
};

struct synthfs_file_node {
	off_t f_size;
};

struct synthfs_symlink_node {
	int s_length;
	char *s_symlinktarget;				/* Dynamically allocated */
};


struct synthfsnode
{
	TAILQ_ENTRY(synthfsnode) s_sibling;		/* synthfsnodes in a given directory */
    enum synthfsnodetype s_type;
	struct synthfsnode *s_parent;
	struct vnode *s_vp;
	char *s_name;
	struct lock__bsd__	s_lock;
	unsigned long s_nodeflags;				/* Internal synthfs flags: IN_CHANGED, IN_MODIFIED, etc. */
	unsigned long s_pflags;					/* File system flags: IMMUTABLE, etc. */
	unsigned long s_nodeid;
	unsigned long s_generation;
	mode_t s_mode;
	short s_linkcount;
	uid_t s_uid;
	gid_t s_gid;
	dev_t s_rdev;
	struct timeval s_createtime;
    struct timeval s_accesstime;
    struct timeval s_modificationtime;
    struct timeval s_changetime;
    struct timeval s_backuptime;
	unsigned long s_flags;					/* inode flags: IMMUTABLE, APPEND, etc. */
	unsigned long s_script;
	unsigned long s_finderInfo[8];
	union {
		struct synthfs_dir_node d;
        struct synthfs_file_node f;
        struct synthfs_symlink_node s;
	} s_u;
};

#define ROOT_DIRID	2
#define FIRST_SYNTHFS_ID 0x10

/* These flags are kept in flags. */
#define IN_ACCESS               0x0001          /* Access time update request. */
#define IN_CHANGE               0x0002          /* Change time update request. */
#define IN_UPDATE               0x0004          /* Modification time update request. */
#define IN_MODIFIED     		0x0008          /* Node has been modified. */
#define IN_RENAME               0x0010          /* Node is being renamed. */
//#define IN_SHLOCK               0x0020          /* File has shared lock. */
//#define IN_EXLOCK               0x0040          /* File has exclusive lock. */
//#define IN_ALLOCATING			0x1000          /* vnode is in transit, wait or ignore */
//#define IN_WANT                 0x2000          /* Its being waited for */

#define SYNTHFSTIMES(sp, t1, t2) {						\
	if ((sp)->s_nodeflags & (IN_ACCESS | IN_CHANGE | IN_UPDATE)) {	\
		(sp)->s_nodeflags |= IN_MODIFIED;				\
		if ((sp)->s_nodeflags & IN_ACCESS) {			\
			(sp)->s_accesstime = *(t1);			\
		};											\
		if ((sp)->s_nodeflags & IN_UPDATE) {			\
			(sp)->s_modificationtime = *(t2);			\
		}											\
		if ((sp)->s_nodeflags & IN_CHANGE) {			\
			(sp)->s_changetime = time;			\
		};											\
		(sp)->s_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_UPDATE);	\
	}								\
}

#define ATTR_REF_DATA(attrrefptr) (((char *)(attrrefptr)) + ((attrrefptr)->attr_dataoffset))

#define STOV(SP) ((SP)->s_vp)

#define VTOS(VP) ((struct synthfsnode *)((VP)->v_data))

#define VTOVFS(VP) ((VP)->v_mount)
#define	STOVFS(HP) ((SP)->s_vp->v_mount)
#define SFSTOVFS(SFSMP) ((SFSMP)->sfs_mp)

#define VTOSFS(VP) ((struct synthfs_mntdata *)((VP)->v_mount->mnt_data))
#define	STOTFS(SP) ((struct synthfs_mntdata *)(SP)->s_vp->v_mount->mnt_data)
#define	VFSTOSFS(MP) ((struct synthfs_mntdata *)(MP)->mnt_data)	

#if DEBUG
#define DBG_TRACE(P) printf P;
#define DBG_INIT(P) printf P;
#define DBG_VOP(P) printf P;
//#define DBG_ASSERT(a) { if (!(a)) { panic("File "__FILE__", line %d: assertion '%s' failed.\n", __LINE__, #a); } }
  #define DBG_ASSERT(a) { if (!(a)) { Debugger("Oops - File __FILE__ , line __LINE__: assertion '"#a"' failed."); } }
#else
#define DBG_TRACE(P)
#define DBG_INIT(P)
#define DBG_VOP(P)
#define DBG_ASSERT(a)
#endif

extern int (**synthfs_vnodeop_p)(void *);

__BEGIN_DECLS
int	synthfs_mount __P((struct mount *, char *, caddr_t, struct nameidata *, struct proc *));
int	synthfs_start __P((struct mount *, int, struct proc *));
int	synthfs_unmount __P((struct mount *, int, struct proc *));
int	synthfs_root __P((struct mount *, struct vnode **));
int	synthfs_quotactl __P((struct mount *, int, uid_t, caddr_t, struct proc *));
int	synthfs_statfs __P((struct mount *, struct statfs *, struct proc *));
int	synthfs_sync __P((struct mount *, int, struct ucred *, struct proc *));
int	synthfs_vget __P((struct mount *, void *ino, struct vnode **));
int	synthfs_fhtovp __P((struct mount *, struct fid *, struct mbuf *, struct vnode **, int *, struct ucred **));
int	synthfs_vptofh __P((struct vnode *, struct fid *));
int	synthfs_init __P((struct vfsconf *));
int	synthfs_sysctl __P((int *, u_int, void *, size_t *, void *, size_t, struct proc *));

int	synthfs_create __P((struct vop_create_args *));
int	synthfs_open __P((struct vop_open_args *));
int	synthfs_mmap __P((struct vop_mmap_args *));
int	synthfs_access __P((struct vop_access_args *));
int	synthfs_getattr __P((struct vop_getattr_args *));
int synthfs_setattr __P((struct vop_setattr_args *));
int synthfs_rename __P((struct vop_rename_args *));
int	synthfs_select __P((struct vop_select_args *));
int synthfs_remove __P((struct vop_remove_args *));
int synthfs_mkdir __P((struct vop_mkdir_args *));
int	synthfs_rmdir __P((struct vop_rmdir_args *));
int synthfs_symlink __P((struct vop_symlink_args *));
int synthfs_readlink __P((struct vop_readlink_args *));
int	synthfs_readdir __P((struct vop_readdir_args *));
int synthfs_cached_lookup __P((struct vop_cachedlookup_args *));
int	synthfs_lookup __P((struct vop_cachedlookup_args *));
int	synthfs_pathconf __P((struct vop_pathconf_args *));
int synthfs_update __P((struct vop_update_args *));
	
int	synthfs_lock __P((struct vop_lock_args *));
int	synthfs_unlock __P((struct vop_unlock_args *));
int	synthfs_islocked __P((struct vop_islocked_args *));

int	synthfs_inactive __P((struct vop_inactive_args*));
int	synthfs_reclaim __P((struct vop_reclaim_args*));

void synthfs_setupuio __P((struct iovec *iov, struct uio *uio, void *buffer, size_t bufsize, enum uio_seg space, enum uio_rw direction, struct proc *p));
int synthfs_new_directory __P((struct mount *mp, struct vnode *dp, const char *name, unsigned long nodeid, mode_t mode, struct proc *p, struct vnode **vpp));
int synthfs_new_symlink __P((struct mount *mp, struct vnode *dp, const char *name, unsigned long nodeid, char *targetstring, struct proc *p, struct vnode **vpp));
long synthfs_adddirentry __P((u_int32_t fileno, u_int8_t type, const char *name, struct uio *uio));
int synthfs_remove_entry __P((struct vnode *vp));
int synthfs_remove_directory __P((struct vnode *vp));
int synthfs_remove_symlink __P((struct vnode *vp));
int synthfs_move_rename_entry __P((struct vnode *source_vp, struct vnode *newparent_vp, char *newname));
int synthfs_derive_vnode_path __P((struct vnode *vp, char *vnpath, size_t pathbuffersize));

#endif /* __SYNTHFS_H__ */
