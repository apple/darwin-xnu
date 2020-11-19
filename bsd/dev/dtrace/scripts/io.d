/*
 * Copyright (c) 2007 Apple, Inc. All rights reserved.
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

#pragma D depends_on library darwin.d
#pragma D depends_on module mach_kernel
#pragma D depends_on provider io

inline int B_WRITE = 0x0000;
#pragma D binding "1.0" B_WRITE
inline int B_READ = 0x0001;
#pragma D binding "1.0" B_READ
inline int B_ASYNC = 0x0002;
#pragma D binding "1.0" B_ASYNC
inline int B_NOCACHE = 0x0004;
#pragma D binding "1.0" B_NOCACHE
inline int B_DELWRI = 0x0008;
#pragma D binding "1.0" B_DELWRI
inline int B_LOCKED = 0x0010;
#pragma D binding "1.0" B_LOCKED
inline int B_PHYS = 0x0020;
#pragma D binding "1.0" B_PHYS
inline int B_CLUSTER = 0x0040;
#pragma D binding "1.0" B_CLUSTER
inline int B_PAGEIO = 0x0080;
#pragma D binding "1.0" B_PAGEIO
inline int B_META = 0x0100;
#pragma D binding "1.0" B_META
inline int B_RAW = 0x0200;
#pragma D binding "1.0" B_RAW
inline int B_FUA = 0x0400;
#pragma D binding "1.0" B_FUA
inline int B_PASSIVE = 0x0800;
#pragma D binding "1.0" B_PASSIVE

typedef struct bufinfo {
	int b_flags;			/* buffer status */
	size_t b_bcount;		/* number of bytes */
	caddr_t b_addr;			/* buffer address */
	uint64_t b_lblkno;		/* block # on device */
	uint64_t b_blkno;		/* expanded block # on device */
	size_t b_resid;			/* # of bytes not transferred */
	size_t b_bufsize;		/* size of allocated buffer */
	caddr_t b_iodone;		/* I/O completion routine */
	int b_error;			/* expanded error field */
	dev_t b_edev;			/* extended device */
} bufinfo_t;

#pragma D binding "1.0" translator
translator bufinfo_t < struct buf *B > {
	b_flags = B->b_flags;
	b_addr = (caddr_t)B->b_datap;
	b_bcount = B->b_bcount;
	b_lblkno = B->b_lblkno;
	b_blkno = B->b_blkno;
	b_resid = B->b_resid;
	b_bufsize = B->b_bufsize;
	b_iodone = (caddr_t)B->b_iodone;
	b_error = B->b_error;
	b_edev = B->b_dev;
};

typedef struct devinfo {
	int dev_major;			/* major number */
	int dev_minor;			/* minor number */
	int dev_instance;		/* instance number */
	string dev_name;		/* name of device */
	string dev_statname;		/* name of device + instance/minor */
	string dev_pathname;		/* pathname of device */
} devinfo_t;

#pragma D binding "1.0" translator
translator devinfo_t < struct buf *B > {
	dev_major = getmajor(B->b_dev);
	dev_minor = getminor(B->b_dev);
	dev_instance = getminor(B->b_dev);
	dev_name = "??"; /* XXX */
	dev_statname = "??"; /* XXX */
	dev_pathname = "??"; /* XXX */
};

typedef off_t offset_t;

typedef struct fileinfo {
	string fi_name;			/* name (basename of fi_pathname) */
	string fi_dirname;		/* directory (dirname of fi_pathname) */
	string fi_pathname;		/* full pathname */
	offset_t fi_offset;		/* offset within file */
	string fi_fs;			/* filesystem */
	string fi_mount;		/* mount point of file system */
	int fi_oflags;          /* open(2) flags for file descriptor */
} fileinfo_t;

#pragma D binding "1.0" translator
translator fileinfo_t < struct buf *B > {
	fi_name = B->b_vp->v_name == NULL ? "<unknown (NULL v_name)>" : B->b_vp->v_name;

	fi_dirname = B->b_vp->v_parent == NULL ? "<unknown (NULL v_parent)>" :
			(B->b_vp->v_parent->v_name == NULL ? "<unknown (NULL v_name)>" : B->b_vp->v_parent->v_name);

	fi_pathname = strjoin("??/",
			strjoin(B->b_vp->v_parent == NULL ? "<unknown (NULL v_parent)>" :
				(B->b_vp->v_parent->v_name == NULL ? "<unknown (NULL v_name)>" : B->b_vp->v_parent->v_name),
				strjoin("/",
					B->b_vp->v_name == NULL ? "<unknown (NULL v_name)>" : B->b_vp->v_name)));

	fi_offset = B->b_upl == NULL ? -1 : ((upl_t)B->b_upl)->u_offset;

	fi_fs = B->b_vp->v_mount->mnt_vtable->vfc_name;

	fi_mount = B->b_vp->v_mount->mnt_vnodecovered == NULL ? "/" : B->b_vp->v_mount->mnt_vnodecovered->v_name;

	fi_oflags = 0;
};

/*
 * The following inline constants can be used to examine fi_oflags when using
 * the fds[] array or a translated fileglob *.  Note that the various open
 * flags behave as a bit-field *except* for O_RDONLY, O_WRONLY, and O_RDWR.
 * To test the open mode, you write code similar to that used with the fcntl(2)
 * F_GET[X]FL command, such as: if ((fi_oflags & O_ACCMODE) == O_WRONLY).
 */
inline int O_ACCMODE = 0x0003;
#pragma D binding "1.1" O_ACCMODE

inline int O_RDONLY = 0x0000;
#pragma D binding "1.1" O_RDONLY
inline int O_WRONLY = 0x0001;
#pragma D binding "1.1" O_WRONLY
inline int O_RDWR = 0x0002;
#pragma D binding "1.1" O_RDWR

inline int O_NONBLOCK = 0x0004;
#pragma D binding "1.1" O_NONBLOCK
inline int O_APPEND = 0x0008;
#pragma D binding "1.1" O_APPEND
inline int O_SHLOCK = 0x0010;
#pragma D binding "1.1" O_SHLOCK
inline int O_EXLOCK = 0x0020;
#pragma D binding "1.1" O_EXLOCK
inline int O_ASYNC = 0x0040;
#pragma D binding "1.1" O_ASYNC
inline int O_SYNC = 0x0080;
#pragma D binding "1.1" O_SYNC
inline int O_NOFOLLOW = 0x0100;
#pragma D binding "1.1" O_NOFOLLOW
inline int O_CREAT = 0x0200;
#pragma D binding "1.1" O_CREAT
inline int O_TRUNC = 0x0400;
#pragma D binding "1.1" O_TRUNC
inline int O_EXCL = 0x0800;
#pragma D binding "1.1" O_EXCL
inline int O_EVTONLY = 0x8000;
#pragma D binding "1.1" O_EVTONLY
inline int O_NOCTTY = 0x20000;
#pragma D binding "1.1" O_NOCTTY
inline int O_DIRECTORY = 0x100000;
#pragma D binding "1.1" O_DIRECTORY
inline int O_SYMLINK = 0x200000;
#pragma D binding "1.1" O_SYMLINK
inline int O_NOFOLLOW_ANY = 0x20000000;
#pragma D binding "1.1" O_NOFOLLOW_ANY

/* From bsd/sys/file_internal.h */
inline int DTYPE_VNODE = 1;
#pragma D binding "1.1" DTYPE_VNODE
inline int DTYPE_SOCKET = 2;
#pragma D binding "1.1" DTYPE_SOCKET
inline int DTYPE_PSXSHM = 3;
#pragma D binding "1.1" DTYPE_PSXSHM
inline int DTYPE_PSXSEM = 4;
#pragma D binding "1.1" DTYPE_PSXSEM
inline int DTYPE_KQUEUE = 5;
#pragma D binding "1.1" DTYPE_KQUEUE
inline int DTYPE_PIPE = 6;
#pragma D binding "1.1" DTYPE_PIPE
inline int DTYPE_FSEVENTS = 7;
#pragma D binding "1.1" DTYPE_FSEVENTS

#pragma D binding "1.1" translator
translator fileinfo_t < struct fileglob *F > {
	fi_name = (F == NULL) ? "<none>" :
		F->fg_ops->fo_type == DTYPE_VNODE ?
			((struct vnode *)F->fg_data)->v_name == NULL ? "<unknown (NULL v_name)>" : ((struct vnode *)F->fg_data)->v_name :
		F->fg_ops->fo_type == DTYPE_SOCKET ? "<socket>" :
		F->fg_ops->fo_type == DTYPE_PSXSHM ? "<shared memory>" :
		F->fg_ops->fo_type == DTYPE_PSXSEM ? "<semaphore>" :
		F->fg_ops->fo_type == DTYPE_KQUEUE ? "<kqueue>" :
		F->fg_ops->fo_type == DTYPE_PIPE ? "<pipe>" :
		F->fg_ops->fo_type == DTYPE_FSEVENTS ? "<fsevents>" : "<unknown (BAD fo_type)>";

	fi_dirname = (F == NULL) ? "<none>" :
		F->fg_ops->fo_type != DTYPE_VNODE ? "<unknown (not a vnode)>" :
			((struct vnode *)F->fg_data)->v_parent == NULL ? "<unknown (NULL v_parent)>" :
			(((struct vnode *)F->fg_data)->v_parent->v_name == NULL ? "<unknown (NULL v_name)>" :
			 ((struct vnode *)F->fg_data)->v_parent->v_name);

	fi_pathname = (F == NULL) ? "<none>" :
		F->fg_ops->fo_type != DTYPE_VNODE ? "<unknown (not a vnode)>" :
			strjoin("??/",
			strjoin(((struct vnode *)F->fg_data)->v_parent == NULL ? "<unknown (NULL v_parent)>" :
				(((struct vnode *)F->fg_data)->v_parent->v_name == NULL ? "<unknown (NULL v_name)>" :
				 ((struct vnode *)F->fg_data)->v_parent->v_name),
				strjoin("/",
					((struct vnode *)F->fg_data)->v_name == NULL ? "<unknown (NULL v_name)>" :
					((struct vnode *)F->fg_data)->v_name)));

	fi_offset = (F == NULL) ? 0 :
			F->fg_offset;

	fi_fs = (F == NULL) ? "<none>" :
		F->fg_ops->fo_type != DTYPE_VNODE ? "<unknown (not a vnode)>" :
			((struct vnode *)F->fg_data)->v_mount->mnt_vtable->vfc_name;

	fi_mount = (F == NULL) ? "<none>" :
		F->fg_ops->fo_type != DTYPE_VNODE ? "<unknown (not a vnode)>" :
			((struct vnode *)F->fg_data)->v_mount->mnt_vnodecovered == NULL ? "/" :
			((struct vnode *)F->fg_data)->v_mount->mnt_vnodecovered->v_name;

	fi_oflags = (F == NULL) ? 0 :
			F->fg_flag - 1; /* Subtract one to map FREAD/FWRITE bitfield to O_RD/WR open() flags. */
};

inline fileinfo_t fds[int fd] = xlate <fileinfo_t> (
	(fd >= 0 && fd <= curproc->p_fd->fd_lastfile) ?
		(struct fileglob *)(curproc->p_fd->fd_ofiles[fd]->fp_glob) :
		(struct fileglob *)NULL);

#pragma D attributes Stable/Stable/Common fds
#pragma D binding "1.1" fds

#pragma D binding "1.2" translator
translator fileinfo_t < struct vnode *V > {
	fi_name = V->v_name == NULL ? "<unknown (NULL v_name)>" : V->v_name;

	fi_dirname = V->v_parent == NULL ? "<unknown (NULL v_parent)>" :
			(V->v_parent->v_name == NULL ? "<unknown (NULL v_name)>" : V->v_parent->v_name);

	fi_pathname = strjoin("??/",
			strjoin(V->v_parent == NULL ? "<unknown (NULL v_parent)>" :
				(V->v_parent->v_name == NULL ? "<unknown (NULL v_name)>" : V->v_parent->v_name),
				strjoin("/",
					V->v_name == NULL ? "<unknown (NULL v_name)>" : V->v_name)));

	fi_fs = V->v_mount->mnt_vtable->vfc_name;

	fi_mount = V->v_mount->mnt_vnodecovered == NULL ? "/" : V->v_mount->mnt_vnodecovered->v_name;
};

