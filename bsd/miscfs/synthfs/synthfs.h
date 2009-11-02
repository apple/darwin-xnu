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

#include  <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
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
			struct timeval  _tv;				\
									\
			microtime(&_tv);					\
			(sp)->s_changetime = _tv;			\
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
int	synthfs_mount (struct mount *, vnode_t, user_addr_t, vfs_context_t context);
int	synthfs_start (struct mount *, int, vfs_context_t context);
int	synthfs_unmount (struct mount *, int, vfs_context_t context);
int	synthfs_root (struct mount *, struct vnode **, vfs_context_t context);
int	synthfs_vfs_getattr (mount_t mp, struct vfs_attr *fsap, vfs_context_t context);
int	synthfs_sync (struct mount *, int, vfs_context_t context);
int	synthfs_vget (struct mount *, ino64_t ino, struct vnode **, vfs_context_t context);
int	synthfs_fhtovp (struct mount *, int, unsigned char *,  struct vnode **, vfs_context_t context);
int	synthfs_vptofh (struct vnode *, int *, unsigned char *, vfs_context_t context);
int	synthfs_init (struct vfsconf *);
int	synthfs_sysctl (int *, u_int, user_addr_t, size_t *, user_addr_t, size_t, vfs_context_t context);

int	synthfs_create (struct vnop_create_args *);
int	synthfs_open (struct vnop_open_args *);
int	synthfs_mmap (struct vnop_mmap_args *);
int	synthfs_getattr (struct vnop_getattr_args *);
int	synthfs_setattr (struct vnop_setattr_args *);
int	synthfs_rename (struct vnop_rename_args *);
int	synthfs_select (struct vnop_select_args *);
int	synthfs_remove (struct vnop_remove_args *);
int	synthfs_mkdir (struct vnop_mkdir_args *);
int	synthfs_rmdir (struct vnop_rmdir_args *);
int	synthfs_symlink (struct vnop_symlink_args *);
int	synthfs_readlink (struct vnop_readlink_args *);
int	synthfs_readdir (struct vnop_readdir_args *);
int	synthfs_cached_lookup (struct vnop_lookup_args *);
int	synthfs_lookup (struct vnop_lookup_args *);
int	synthfs_pathconf (struct vnop_pathconf_args *);
	

int	synthfs_inactive (struct vnop_inactive_args*);
int	synthfs_reclaim (struct vnop_reclaim_args*);

void synthfs_setupuio (struct iovec *iov, struct uio *uio, void *buffer, size_t bufsize, enum uio_seg space, enum uio_rw direction, proc_t p);
int synthfs_new_directory (mount_t mp, vnode_t dp, const char *name, unsigned long nodeid, mode_t mode, proc_t p, vnode_t *vpp);
int synthfs_new_symlink (mount_t mp, vnode_t dp, const char *name, unsigned long nodeid, char *targetstring, proc_t p, vnode_t *vpp);
long synthfs_adddirentry (u_int32_t fileno, u_int8_t type, const char *name, struct uio *uio);
int synthfs_remove_entry (struct vnode *vp);
int synthfs_remove_directory (struct vnode *vp);
int synthfs_remove_symlink (struct vnode *vp);
int synthfs_move_rename_entry (struct vnode *source_vp, struct vnode *newparent_vp, char *newname);
int synthfs_derive_vnode_path (struct vnode *vp, char *vnpath, size_t pathbuffersize);
int synthfs_update(struct vnode *vp, struct timeval *access, struct timeval *modify, int waitfor);

#endif /* __APPLE_API_PRIVATE */
#endif /* __SYNTHFS_H__ */
