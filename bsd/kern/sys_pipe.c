/*
 * Copyright (c) 1996 John S. Dyson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Absolutely no warranty of function or purpose is made by the author
 *    John S. Dyson.
 * 4. Modifications may be freely made to this file if the above conditions
 *    are met.
 */
/*
 * Copyright (c) 2003-2020 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

/*
 * This file contains a high-performance replacement for the socket-based
 * pipes scheme originally used in FreeBSD/4.4Lite.  It does not support
 * all features of sockets, but does do everything that pipes normally
 * do.
 *
 * Pipes are implemented as circular buffers. Following are the valid states in pipes operations
 *
 *      _________________________________
 * 1.  |_________________________________| r=w, c=0
 *
 *      _________________________________
 * 2.  |__r:::::wc_______________________| r <= w , c > 0
 *
 *      _________________________________
 * 3.  |::::wc_____r:::::::::::::::::::::| r>w , c > 0
 *
 *      _________________________________
 * 4.  |:::::::wrc:::::::::::::::::::::::| w=r, c = Max size
 *
 *
 *  Nomenclature:-
 *  a-z define the steps in a program flow
 *  1-4 are the states as defined aboe
 *  Action: is what file operation is done on the pipe
 *
 *  Current:None  Action: initialize with size M=200
 *  a. State 1 ( r=0, w=0, c=0)
 *
 *  Current: a    Action: write(100) (w < M)
 *  b. State 2 (r=0, w=100, c=100)
 *
 *  Current: b    Action: write(100) (w = M-w)
 *  c. State 4 (r=0,w=0,c=200)
 *
 *  Current: b    Action: read(70)  ( r < c )
 *  d. State 2(r=70,w=100,c=30)
 *
 *  Current: d	  Action: write(75) ( w < (m-w))
 *  e. State 2 (r=70,w=175,c=105)
 *
 *  Current: d    Action: write(110) ( w > (m-w))
 *  f. State 3 (r=70,w=10,c=140)
 *
 *  Current: d	  Action: read(30) (r >= c )
 *  g. State 1 (r=100,w=100,c=0)
 *
 */

/*
 * This code create half duplex pipe buffers for facilitating file like
 * operations on pipes. The initial buffer is very small, but this can
 * dynamically change to larger sizes based on usage. The buffer size is never
 * reduced. The total amount of kernel memory used is governed by maxpipekva.
 * In case of dynamic expansion limit is reached, the output thread is blocked
 * until the pipe buffer empties enough to continue.
 *
 * In order to limit the resource use of pipes, two sysctls exist:
 *
 * kern.ipc.maxpipekva - This is a hard limit on the amount of pageable
 * address space available to us in pipe_map.
 *
 * Memory usage may be monitored through the sysctls
 * kern.ipc.pipes, kern.ipc.pipekva.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/file_internal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/syslog.h>
#include <sys/unistd.h>
#include <sys/resourcevar.h>
#include <sys/aio_kern.h>
#include <sys/signalvar.h>
#include <sys/pipe.h>
#include <sys/sysproto.h>
#include <sys/proc_info.h>

#include <security/audit/audit.h>

#include <sys/kdebug.h>

#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <vm/vm_kern.h>
#include <libkern/OSAtomic.h>
#include <libkern/section_keywords.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#define f_flag fp_glob->fg_flag
#define f_ops fp_glob->fg_ops
#define f_data fp_glob->fg_data

struct pipepair {
	lck_mtx_t     pp_mtx;
	struct pipe   pp_rpipe;
	struct pipe   pp_wpipe;
	uint64_t      pp_pipe_id;       /* unique ID shared by both pipe ends */
};

#define PIPE_PAIR(pipe) \
	        __container_of(PIPE_MTX(pipe), struct pipepair, pp_mtx)

/*
 * interfaces to the outside world exported through file operations
 */
static int pipe_read(struct fileproc *fp, struct uio *uio,
    int flags, vfs_context_t ctx);
static int pipe_write(struct fileproc *fp, struct uio *uio,
    int flags, vfs_context_t ctx);
static int pipe_close(struct fileglob *fg, vfs_context_t ctx);
static int pipe_select(struct fileproc *fp, int which, void * wql,
    vfs_context_t ctx);
static int pipe_kqfilter(struct fileproc *fp, struct knote *kn,
    struct kevent_qos_s *kev);
static int pipe_ioctl(struct fileproc *fp, u_long cmd, caddr_t data,
    vfs_context_t ctx);
static int pipe_drain(struct fileproc *fp, vfs_context_t ctx);

static const struct fileops pipeops = {
	.fo_type     = DTYPE_PIPE,
	.fo_read     = pipe_read,
	.fo_write    = pipe_write,
	.fo_ioctl    = pipe_ioctl,
	.fo_select   = pipe_select,
	.fo_close    = pipe_close,
	.fo_drain    = pipe_drain,
	.fo_kqfilter = pipe_kqfilter,
};

static void filt_pipedetach(struct knote *kn);

static int filt_pipenotsup(struct knote *kn, long hint);
static int filt_pipenotsuptouch(struct knote *kn, struct kevent_qos_s *kev);
static int filt_pipenotsupprocess(struct knote *kn, struct kevent_qos_s *kev);

static int filt_piperead(struct knote *kn, long hint);
static int filt_pipereadtouch(struct knote *kn, struct kevent_qos_s *kev);
static int filt_pipereadprocess(struct knote *kn, struct kevent_qos_s *kev);

static int filt_pipewrite(struct knote *kn, long hint);
static int filt_pipewritetouch(struct knote *kn, struct kevent_qos_s *kev);
static int filt_pipewriteprocess(struct knote *kn, struct kevent_qos_s *kev);

SECURITY_READ_ONLY_EARLY(struct filterops) pipe_nfiltops = {
	.f_isfd    = 1,
	.f_detach  = filt_pipedetach,
	.f_event   = filt_pipenotsup,
	.f_touch   = filt_pipenotsuptouch,
	.f_process = filt_pipenotsupprocess,
};

SECURITY_READ_ONLY_EARLY(struct filterops) pipe_rfiltops = {
	.f_isfd    = 1,
	.f_detach  = filt_pipedetach,
	.f_event   = filt_piperead,
	.f_touch   = filt_pipereadtouch,
	.f_process = filt_pipereadprocess,
};

SECURITY_READ_ONLY_EARLY(struct filterops) pipe_wfiltops = {
	.f_isfd    = 1,
	.f_detach  = filt_pipedetach,
	.f_event   = filt_pipewrite,
	.f_touch   = filt_pipewritetouch,
	.f_process = filt_pipewriteprocess,
};

#if PIPE_SYSCTLS
static int nbigpipe;      /* for compatibility sake. no longer used */
#endif
static int amountpipes;   /* total number of pipes in system */
static int amountpipekva; /* total memory used by pipes */

static _Atomic uint64_t pipe_unique_id = 1;

int maxpipekva __attribute__((used)) = PIPE_KVAMAX;  /* allowing 16MB max. */

#if PIPE_SYSCTLS
SYSCTL_DECL(_kern_ipc);

SYSCTL_INT(_kern_ipc, OID_AUTO, maxpipekva, CTLFLAG_RD | CTLFLAG_LOCKED,
    &maxpipekva, 0, "Pipe KVA limit");
SYSCTL_INT(_kern_ipc, OID_AUTO, maxpipekvawired, CTLFLAG_RW | CTLFLAG_LOCKED,
    &maxpipekvawired, 0, "Pipe KVA wired limit");
SYSCTL_INT(_kern_ipc, OID_AUTO, pipes, CTLFLAG_RD | CTLFLAG_LOCKED,
    &amountpipes, 0, "Current # of pipes");
SYSCTL_INT(_kern_ipc, OID_AUTO, bigpipes, CTLFLAG_RD | CTLFLAG_LOCKED,
    &nbigpipe, 0, "Current # of big pipes");
SYSCTL_INT(_kern_ipc, OID_AUTO, pipekva, CTLFLAG_RD | CTLFLAG_LOCKED,
    &amountpipekva, 0, "Pipe KVA usage");
SYSCTL_INT(_kern_ipc, OID_AUTO, pipekvawired, CTLFLAG_RD | CTLFLAG_LOCKED,
    &amountpipekvawired, 0, "Pipe wired KVA usage");
#endif

static int pipepair_alloc(struct pipe **rpipe, struct pipe **wpipe);
static void pipeclose(struct pipe *cpipe);
static void pipe_free_kmem(struct pipe *cpipe);
static int pipespace(struct pipe *cpipe, int size);
static int choose_pipespace(unsigned long current, unsigned long expected);
static int expand_pipespace(struct pipe *p, int target_size);
static void pipeselwakeup(struct pipe *cpipe, struct pipe *spipe);
static __inline int pipeio_lock(struct pipe *cpipe, int catch);
static __inline void pipeio_unlock(struct pipe *cpipe);

static LCK_GRP_DECLARE(pipe_mtx_grp, "pipe");
static ZONE_DECLARE(pipe_zone, "pipe zone", sizeof(struct pipepair), ZC_NONE);

#define MAX_PIPESIZE(pipe)              ( MAX(PIPE_SIZE, (pipe)->pipe_buffer.size) )

SYSINIT(vfs, SI_SUB_VFS, SI_ORDER_ANY, pipeinit, NULL);

#if defined(XNU_TARGET_OS_OSX)
/* Bitmap for things to touch in pipe_touch() */
#define PIPE_ATIME      0x00000001      /* time of last access */
#define PIPE_MTIME      0x00000002      /* time of last modification */
#define PIPE_CTIME      0x00000004      /* time of last status change */

static void
pipe_touch(struct pipe *tpipe, int touch)
{
	struct timespec now;

	nanotime(&now);

	if (touch & PIPE_ATIME) {
		tpipe->st_atimespec.tv_sec  = now.tv_sec;
		tpipe->st_atimespec.tv_nsec = now.tv_nsec;
	}

	if (touch & PIPE_MTIME) {
		tpipe->st_mtimespec.tv_sec  = now.tv_sec;
		tpipe->st_mtimespec.tv_nsec = now.tv_nsec;
	}

	if (touch & PIPE_CTIME) {
		tpipe->st_ctimespec.tv_sec  = now.tv_sec;
		tpipe->st_ctimespec.tv_nsec = now.tv_nsec;
	}
}
#endif

static const unsigned int pipesize_blocks[] = {512, 1024, 2048, 4096, 4096 * 2, PIPE_SIZE, PIPE_SIZE * 4 };

/*
 * finds the right size from possible sizes in pipesize_blocks
 * returns the size which matches max(current,expected)
 */
static int
choose_pipespace(unsigned long current, unsigned long expected)
{
	int i = sizeof(pipesize_blocks) / sizeof(unsigned int) - 1;
	unsigned long target;

	/*
	 * assert that we always get an atomic transaction sized pipe buffer,
	 * even if the system pipe buffer high-water mark has been crossed.
	 */
	assert(PIPE_BUF == pipesize_blocks[0]);

	if (expected > current) {
		target = expected;
	} else {
		target = current;
	}

	while (i > 0 && pipesize_blocks[i - 1] > target) {
		i = i - 1;
	}

	return pipesize_blocks[i];
}


/*
 * expand the size of pipe while there is data to be read,
 * and then free the old buffer once the current buffered
 * data has been transferred to new storage.
 * Required: PIPE_LOCK and io lock to be held by caller.
 * returns 0 on success or no expansion possible
 */
static int
expand_pipespace(struct pipe *p, int target_size)
{
	struct pipe tmp, oldpipe;
	int error;
	tmp.pipe_buffer.buffer = 0;

	if (p->pipe_buffer.size >= (unsigned) target_size) {
		return 0; /* the existing buffer is max size possible */
	}

	/* create enough space in the target */
	error = pipespace(&tmp, target_size);
	if (error != 0) {
		return error;
	}

	oldpipe.pipe_buffer.buffer = p->pipe_buffer.buffer;
	oldpipe.pipe_buffer.size = p->pipe_buffer.size;

	memcpy(tmp.pipe_buffer.buffer, p->pipe_buffer.buffer, p->pipe_buffer.size);
	if (p->pipe_buffer.cnt > 0 && p->pipe_buffer.in <= p->pipe_buffer.out) {
		/* we are in State 3 and need extra copying for read to be consistent */
		memcpy(&tmp.pipe_buffer.buffer[p->pipe_buffer.size], p->pipe_buffer.buffer, p->pipe_buffer.size);
		p->pipe_buffer.in += p->pipe_buffer.size;
	}

	p->pipe_buffer.buffer = tmp.pipe_buffer.buffer;
	p->pipe_buffer.size = tmp.pipe_buffer.size;


	pipe_free_kmem(&oldpipe);
	return 0;
}

/*
 * The pipe system call for the DTYPE_PIPE type of pipes
 *
 * returns:
 *  FREAD  | fd0 | -->[struct rpipe] --> |~~buffer~~| \
 *                                                    (pipe_mutex)
 *  FWRITE | fd1 | -->[struct wpipe] --X              /
 */

/* ARGSUSED */
int
pipe(proc_t p, __unused struct pipe_args *uap, int32_t *retval)
{
	struct fileproc *rf, *wf;
	struct pipe *rpipe, *wpipe;
	int error;

	error = pipepair_alloc(&rpipe, &wpipe);
	if (error) {
		return error;
	}

	/*
	 * for now we'll create half-duplex pipes(refer returns section above).
	 * this is what we've always supported..
	 */

	error = falloc(p, &rf, &retval[0], vfs_context_current());
	if (error) {
		goto freepipes;
	}
	rf->f_flag = FREAD;
	rf->f_data = (caddr_t)rpipe;
	rf->f_ops = &pipeops;

	error = falloc(p, &wf, &retval[1], vfs_context_current());
	if (error) {
		fp_free(p, retval[0], rf);
		goto freepipes;
	}
	wf->f_flag = FWRITE;
	wf->f_data = (caddr_t)wpipe;
	wf->f_ops = &pipeops;

	rpipe->pipe_peer = wpipe;
	wpipe->pipe_peer = rpipe;

#if CONFIG_MACF
	/*
	 * XXXXXXXX SHOULD NOT HOLD FILE_LOCK() XXXXXXXXXXXX
	 *
	 * struct pipe represents a pipe endpoint.  The MAC label is shared
	 * between the connected endpoints.  As a result mac_pipe_label_init() and
	 * mac_pipe_label_associate() should only be called on one of the endpoints
	 * after they have been connected.
	 */
	mac_pipe_label_init(rpipe);
	mac_pipe_label_associate(kauth_cred_get(), rpipe);
	wpipe->pipe_label = rpipe->pipe_label;
#endif
	proc_fdlock_spin(p);
	procfdtbl_releasefd(p, retval[0], NULL);
	procfdtbl_releasefd(p, retval[1], NULL);
	fp_drop(p, retval[0], rf, 1);
	fp_drop(p, retval[1], wf, 1);
	proc_fdunlock(p);
	return 0;

freepipes:
	pipeclose(rpipe);
	pipeclose(wpipe);
	return error;
}

int
pipe_stat(struct pipe *cpipe, void *ub, int isstat64)
{
#if CONFIG_MACF
	int error;
#endif
	int     pipe_size = 0;
	int     pipe_count;
	struct stat *sb = (struct stat *)0;     /* warning avoidance ; protected by isstat64 */
	struct stat64 * sb64 = (struct stat64 *)0;  /* warning avoidance ; protected by isstat64 */

	if (cpipe == NULL) {
		return EBADF;
	}
	PIPE_LOCK(cpipe);

#if CONFIG_MACF
	error = mac_pipe_check_stat(kauth_cred_get(), cpipe);
	if (error) {
		PIPE_UNLOCK(cpipe);
		return error;
	}
#endif
	if (cpipe->pipe_buffer.buffer == 0) {
		/* must be stat'ing the write fd */
		if (cpipe->pipe_peer) {
			/* the peer still exists, use it's info */
			pipe_size  = MAX_PIPESIZE(cpipe->pipe_peer);
			pipe_count = cpipe->pipe_peer->pipe_buffer.cnt;
		} else {
			pipe_count = 0;
		}
	} else {
		pipe_size  = MAX_PIPESIZE(cpipe);
		pipe_count = cpipe->pipe_buffer.cnt;
	}
	/*
	 * since peer's buffer is setup ouside of lock
	 * we might catch it in transient state
	 */
	if (pipe_size == 0) {
		pipe_size  = MAX(PIPE_SIZE, pipesize_blocks[0]);
	}

	if (isstat64 != 0) {
		sb64 = (struct stat64 *)ub;

		bzero(sb64, sizeof(*sb64));
		sb64->st_mode = S_IFIFO | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
		sb64->st_blksize = pipe_size;
		sb64->st_size = pipe_count;
		sb64->st_blocks = (sb64->st_size + sb64->st_blksize - 1) / sb64->st_blksize;

		sb64->st_uid = kauth_getuid();
		sb64->st_gid = kauth_getgid();

		sb64->st_atimespec.tv_sec  = cpipe->st_atimespec.tv_sec;
		sb64->st_atimespec.tv_nsec = cpipe->st_atimespec.tv_nsec;

		sb64->st_mtimespec.tv_sec  = cpipe->st_mtimespec.tv_sec;
		sb64->st_mtimespec.tv_nsec = cpipe->st_mtimespec.tv_nsec;

		sb64->st_ctimespec.tv_sec  = cpipe->st_ctimespec.tv_sec;
		sb64->st_ctimespec.tv_nsec = cpipe->st_ctimespec.tv_nsec;

		/*
		 * Return a relatively unique inode number based on the current
		 * address of this pipe's struct pipe.  This number may be recycled
		 * relatively quickly.
		 */
		sb64->st_ino = (ino64_t)VM_KERNEL_ADDRHASH((uintptr_t)cpipe);
	} else {
		sb = (struct stat *)ub;

		bzero(sb, sizeof(*sb));
		sb->st_mode = S_IFIFO | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
		sb->st_blksize = pipe_size;
		sb->st_size = pipe_count;
		sb->st_blocks = (sb->st_size + sb->st_blksize - 1) / sb->st_blksize;

		sb->st_uid = kauth_getuid();
		sb->st_gid = kauth_getgid();

		sb->st_atimespec.tv_sec  = cpipe->st_atimespec.tv_sec;
		sb->st_atimespec.tv_nsec = cpipe->st_atimespec.tv_nsec;

		sb->st_mtimespec.tv_sec  = cpipe->st_mtimespec.tv_sec;
		sb->st_mtimespec.tv_nsec = cpipe->st_mtimespec.tv_nsec;

		sb->st_ctimespec.tv_sec  = cpipe->st_ctimespec.tv_sec;
		sb->st_ctimespec.tv_nsec = cpipe->st_ctimespec.tv_nsec;

		/*
		 * Return a relatively unique inode number based on the current
		 * address of this pipe's struct pipe.  This number may be recycled
		 * relatively quickly.
		 */
		sb->st_ino = (ino_t)VM_KERNEL_ADDRHASH((uintptr_t)cpipe);
	}
	PIPE_UNLOCK(cpipe);

	/*
	 * POSIX: Left as 0: st_dev, st_nlink, st_rdev, st_flags, st_gen,
	 * st_uid, st_gid.
	 *
	 * XXX (st_dev) should be unique, but there is no device driver that
	 * XXX is associated with pipes, since they are implemented via a
	 * XXX struct fileops indirection rather than as FS objects.
	 */
	return 0;
}

uint64_t
pipe_id(struct pipe *p)
{
	return PIPE_PAIR(p)->pp_pipe_id;
}

/*
 * Allocate kva for pipe circular buffer, the space is pageable
 * This routine will 'realloc' the size of a pipe safely, if it fails
 * it will retain the old buffer.
 * If it fails it will return ENOMEM.
 */
static int
pipespace(struct pipe *cpipe, int size)
{
	vm_offset_t buffer;

	if (size <= 0) {
		return EINVAL;
	}

	buffer = (vm_offset_t)kheap_alloc(KHEAP_DATA_BUFFERS, size, Z_WAITOK);
	if (!buffer) {
		return ENOMEM;
	}

	/* free old resources if we're resizing */
	pipe_free_kmem(cpipe);
	cpipe->pipe_buffer.buffer = (caddr_t)buffer;
	cpipe->pipe_buffer.size = size;
	cpipe->pipe_buffer.in = 0;
	cpipe->pipe_buffer.out = 0;
	cpipe->pipe_buffer.cnt = 0;

	OSAddAtomic(1, &amountpipes);
	OSAddAtomic(cpipe->pipe_buffer.size, &amountpipekva);

	return 0;
}

/*
 * initialize and allocate VM and memory for pipe
 */
static int
pipepair_alloc(struct pipe **rp_out, struct pipe **wp_out)
{
	struct pipepair *pp = zalloc(pipe_zone);
	struct pipe *rpipe = &pp->pp_rpipe;
	struct pipe *wpipe = &pp->pp_wpipe;

	if (pp == NULL) {
		return ENOMEM;
	}

	/*
	 * protect so pipespace or pipeclose don't follow a junk pointer
	 * if pipespace() fails.
	 */
	bzero(pp, sizeof(struct pipepair));
	pp->pp_pipe_id = os_atomic_inc_orig(&pipe_unique_id, relaxed);
	lck_mtx_init(&pp->pp_mtx, &pipe_mtx_grp, LCK_ATTR_NULL);

	rpipe->pipe_mtxp = &pp->pp_mtx;
	wpipe->pipe_mtxp = &pp->pp_mtx;

#if defined(XNU_TARGET_OS_OSX)
	/* Initial times are all the time of creation of the pipe */
	pipe_touch(rpipe, PIPE_ATIME | PIPE_MTIME | PIPE_CTIME);
	pipe_touch(wpipe, PIPE_ATIME | PIPE_MTIME | PIPE_CTIME);
#endif

	/*
	 * allocate the space for the normal I/O direction up
	 * front... we'll delay the allocation for the other
	 * direction until a write actually occurs (most likely it won't)...
	 */
	int error = pipespace(rpipe, choose_pipespace(rpipe->pipe_buffer.size, 0));
	if (__improbable(error)) {
		lck_mtx_destroy(&pp->pp_mtx, &pipe_mtx_grp);
		zfree(pipe_zone, pp);
		return error;
	}

	*rp_out = rpipe;
	*wp_out = wpipe;
	return 0;
}

static void
pipepair_destroy_pipe(struct pipepair *pp, struct pipe *cpipe)
{
	bool can_free;

	pipe_free_kmem(cpipe);

	lck_mtx_lock(&pp->pp_mtx);
	if (__improbable(cpipe->pipe_state & PIPE_DEAD)) {
		panic("double free of pipe %p in pair %p", cpipe, pp);
	}

	cpipe->pipe_state |= PIPE_DEAD;

	can_free = (pp->pp_rpipe.pipe_state & PIPE_DEAD) &&
	    (pp->pp_wpipe.pipe_state & PIPE_DEAD);
	lck_mtx_unlock(&pp->pp_mtx);

	if (can_free) {
		lck_mtx_destroy(&pp->pp_mtx, &pipe_mtx_grp);
		zfree(pipe_zone, pp);
	}
}

/*
 * lock a pipe for I/O, blocking other access
 */
static inline int
pipeio_lock(struct pipe *cpipe, int catch)
{
	int error;
	while (cpipe->pipe_state & PIPE_LOCKFL) {
		cpipe->pipe_state |= PIPE_LWANT;
		error = msleep(cpipe, PIPE_MTX(cpipe), catch ? (PRIBIO | PCATCH) : PRIBIO,
		    "pipelk", 0);
		if (error != 0) {
			return error;
		}
	}
	cpipe->pipe_state |= PIPE_LOCKFL;
	return 0;
}

/*
 * unlock a pipe I/O lock
 */
static inline void
pipeio_unlock(struct pipe *cpipe)
{
	cpipe->pipe_state &= ~PIPE_LOCKFL;
	if (cpipe->pipe_state & PIPE_LWANT) {
		cpipe->pipe_state &= ~PIPE_LWANT;
		wakeup(cpipe);
	}
}

/*
 * wakeup anyone whos blocked in select
 */
static void
pipeselwakeup(struct pipe *cpipe, struct pipe *spipe)
{
	if (cpipe->pipe_state & PIPE_SEL) {
		cpipe->pipe_state &= ~PIPE_SEL;
		selwakeup(&cpipe->pipe_sel);
	}

	KNOTE(&cpipe->pipe_sel.si_note, 1);

	if (spipe && (spipe->pipe_state & PIPE_ASYNC) && spipe->pipe_pgid) {
		if (spipe->pipe_pgid < 0) {
			gsignal(-spipe->pipe_pgid, SIGIO);
		} else {
			proc_signal(spipe->pipe_pgid, SIGIO);
		}
	}
}

/*
 * Read n bytes from the buffer. Semantics are similar to file read.
 * returns: number of bytes read from the buffer
 */
/* ARGSUSED */
static int
pipe_read(struct fileproc *fp, struct uio *uio, __unused int flags,
    __unused vfs_context_t ctx)
{
	struct pipe *rpipe = (struct pipe *)fp->f_data;
	int error;
	int nread = 0;
	u_int size;

	PIPE_LOCK(rpipe);
	++rpipe->pipe_busy;

	error = pipeio_lock(rpipe, 1);
	if (error) {
		goto unlocked_error;
	}

#if CONFIG_MACF
	error = mac_pipe_check_read(kauth_cred_get(), rpipe);
	if (error) {
		goto locked_error;
	}
#endif


	while (uio_resid(uio)) {
		/*
		 * normal pipe buffer receive
		 */
		if (rpipe->pipe_buffer.cnt > 0) {
			/*
			 * # bytes to read is min( bytes from read pointer until end of buffer,
			 *                         total unread bytes,
			 *                         user requested byte count)
			 */
			size = rpipe->pipe_buffer.size - rpipe->pipe_buffer.out;
			if (size > rpipe->pipe_buffer.cnt) {
				size = rpipe->pipe_buffer.cnt;
			}

			size = (u_int) MIN(INT_MAX, MIN((user_size_t)size,
			    (user_size_t)uio_resid(uio)));

			PIPE_UNLOCK(rpipe); /* we still hold io lock.*/
			error = uiomove(
				&rpipe->pipe_buffer.buffer[rpipe->pipe_buffer.out],
				size, uio);
			PIPE_LOCK(rpipe);
			if (error) {
				break;
			}

			rpipe->pipe_buffer.out += size;
			if (rpipe->pipe_buffer.out >= rpipe->pipe_buffer.size) {
				rpipe->pipe_buffer.out = 0;
			}

			rpipe->pipe_buffer.cnt -= size;

			/*
			 * If there is no more to read in the pipe, reset
			 * its pointers to the beginning.  This improves
			 * cache hit stats.
			 */
			if (rpipe->pipe_buffer.cnt == 0) {
				rpipe->pipe_buffer.in = 0;
				rpipe->pipe_buffer.out = 0;
			}
			nread += size;
		} else {
			/*
			 * detect EOF condition
			 * read returns 0 on EOF, no need to set error
			 */
			if ((rpipe->pipe_state & (PIPE_DRAIN | PIPE_EOF)) ||
			    (fileproc_get_vflags(fp) & FPV_DRAIN)) {
				break;
			}

			/*
			 * If the "write-side" has been blocked, wake it up now.
			 */
			if (rpipe->pipe_state & PIPE_WANTW) {
				rpipe->pipe_state &= ~PIPE_WANTW;
				wakeup(rpipe);
			}

			/*
			 * Break if some data was read in previous iteration.
			 */
			if (nread > 0) {
				break;
			}

			/*
			 * Unlock the pipe buffer for our remaining processing.
			 * We will either break out with an error or we will
			 * sleep and relock to loop.
			 */
			pipeio_unlock(rpipe);

			/*
			 * Handle non-blocking mode operation or
			 * wait for more data.
			 */
			if (fp->f_flag & FNONBLOCK) {
				error = EAGAIN;
			} else {
				rpipe->pipe_state |= PIPE_WANTR;
				error = msleep(rpipe, PIPE_MTX(rpipe), PRIBIO | PCATCH, "piperd", 0);
				if (error == 0) {
					error = pipeio_lock(rpipe, 1);
				}
			}
			if (error) {
				goto unlocked_error;
			}
		}
	}
#if CONFIG_MACF
locked_error:
#endif
	pipeio_unlock(rpipe);

unlocked_error:
	--rpipe->pipe_busy;

	/*
	 * PIPE_WANT processing only makes sense if pipe_busy is 0.
	 */
	if ((rpipe->pipe_busy == 0) && (rpipe->pipe_state & PIPE_WANT)) {
		rpipe->pipe_state &= ~(PIPE_WANT | PIPE_WANTW);
		wakeup(rpipe);
	} else if (rpipe->pipe_buffer.cnt < rpipe->pipe_buffer.size) {
		/*
		 * Handle write blocking hysteresis.
		 */
		if (rpipe->pipe_state & PIPE_WANTW) {
			rpipe->pipe_state &= ~PIPE_WANTW;
			wakeup(rpipe);
		}
	}

	if ((rpipe->pipe_buffer.size - rpipe->pipe_buffer.cnt) > 0) {
		pipeselwakeup(rpipe, rpipe->pipe_peer);
	}

#if defined(XNU_TARGET_OS_OSX)
	/* update last read time */
	pipe_touch(rpipe, PIPE_ATIME);
#endif

	PIPE_UNLOCK(rpipe);

	return error;
}

/*
 * perform a write of n bytes into the read side of buffer. Since
 * pipes are unidirectional a write is meant to be read by the otherside only.
 */
static int
pipe_write(struct fileproc *fp, struct uio *uio, __unused int flags,
    __unused vfs_context_t ctx)
{
	int error = 0;
	size_t orig_resid;
	int pipe_size;
	struct pipe *wpipe, *rpipe;
	// LP64todo - fix this!
	orig_resid = (size_t)uio_resid(uio);
	if (orig_resid > LONG_MAX) {
		return EINVAL;
	}
	int space;

	rpipe = (struct pipe *)fp->f_data;

	PIPE_LOCK(rpipe);
	wpipe = rpipe->pipe_peer;

	/*
	 * detect loss of pipe read side, issue SIGPIPE if lost.
	 */
	if (wpipe == NULL || (wpipe->pipe_state & (PIPE_DRAIN | PIPE_EOF)) ||
	    (fileproc_get_vflags(fp) & FPV_DRAIN)) {
		PIPE_UNLOCK(rpipe);
		return EPIPE;
	}
#if CONFIG_MACF
	error = mac_pipe_check_write(kauth_cred_get(), wpipe);
	if (error) {
		PIPE_UNLOCK(rpipe);
		return error;
	}
#endif
	++wpipe->pipe_busy;

	pipe_size = 0;

	/*
	 * need to allocate some storage... we delay the allocation
	 * until the first write on fd[0] to avoid allocating storage for both
	 * 'pipe ends'... most pipes are half-duplex with the writes targeting
	 * fd[1], so allocating space for both ends is a waste...
	 */

	if (wpipe->pipe_buffer.buffer == 0 || (
		    (unsigned)orig_resid > wpipe->pipe_buffer.size - wpipe->pipe_buffer.cnt &&
		    amountpipekva < maxpipekva)) {
		pipe_size = choose_pipespace(wpipe->pipe_buffer.size, wpipe->pipe_buffer.cnt + orig_resid);
	}
	if (pipe_size) {
		/*
		 * need to do initial allocation or resizing of pipe
		 * holding both structure and io locks.
		 */
		if ((error = pipeio_lock(wpipe, 1)) == 0) {
			if (wpipe->pipe_buffer.cnt == 0) {
				error = pipespace(wpipe, pipe_size);
			} else {
				error = expand_pipespace(wpipe, pipe_size);
			}

			pipeio_unlock(wpipe);

			/* allocation failed */
			if (wpipe->pipe_buffer.buffer == 0) {
				error = ENOMEM;
			}
		}
		if (error) {
			/*
			 * If an error occurred unbusy and return, waking up any pending
			 * readers.
			 */
			--wpipe->pipe_busy;
			if ((wpipe->pipe_busy == 0) &&
			    (wpipe->pipe_state & PIPE_WANT)) {
				wpipe->pipe_state &= ~(PIPE_WANT | PIPE_WANTR);
				wakeup(wpipe);
			}
			PIPE_UNLOCK(rpipe);
			return error;
		}
	}

	while (uio_resid(uio)) {
retrywrite:
		space = wpipe->pipe_buffer.size - wpipe->pipe_buffer.cnt;

		/* Writes of size <= PIPE_BUF must be atomic. */
		if ((space < uio_resid(uio)) && (orig_resid <= PIPE_BUF)) {
			space = 0;
		}

		if (space > 0) {
			if ((error = pipeio_lock(wpipe, 1)) == 0) {
				size_t size;       /* Transfer size */
				size_t segsize;    /* first segment to transfer */

				if ((wpipe->pipe_state & (PIPE_DRAIN | PIPE_EOF)) ||
				    (fileproc_get_vflags(fp) & FPV_DRAIN)) {
					pipeio_unlock(wpipe);
					error = EPIPE;
					break;
				}
				/*
				 * If a process blocked in pipeio_lock, our
				 * value for space might be bad... the mutex
				 * is dropped while we're blocked
				 */
				if (space > (int)(wpipe->pipe_buffer.size -
				    wpipe->pipe_buffer.cnt)) {
					pipeio_unlock(wpipe);
					goto retrywrite;
				}

				/*
				 * Transfer size is minimum of uio transfer
				 * and free space in pipe buffer.
				 */
				// LP64todo - fix this!
				if (space > uio_resid(uio)) {
					size = (size_t)uio_resid(uio);
					if (size > LONG_MAX) {
						panic("size greater than LONG_MAX");
					}
				} else {
					size = space;
				}
				/*
				 * First segment to transfer is minimum of
				 * transfer size and contiguous space in
				 * pipe buffer.  If first segment to transfer
				 * is less than the transfer size, we've got
				 * a wraparound in the buffer.
				 */
				segsize = wpipe->pipe_buffer.size -
				    wpipe->pipe_buffer.in;
				if (segsize > size) {
					segsize = size;
				}

				/* Transfer first segment */

				PIPE_UNLOCK(rpipe);
				error = uiomove(&wpipe->pipe_buffer.buffer[wpipe->pipe_buffer.in],
				    (int)segsize, uio);
				PIPE_LOCK(rpipe);

				if (error == 0 && segsize < size) {
					/*
					 * Transfer remaining part now, to
					 * support atomic writes.  Wraparound
					 * happened. (State 3)
					 */
					if (wpipe->pipe_buffer.in + segsize !=
					    wpipe->pipe_buffer.size) {
						panic("Expected pipe buffer "
						    "wraparound disappeared");
					}

					PIPE_UNLOCK(rpipe);
					error = uiomove(
						&wpipe->pipe_buffer.buffer[0],
						(int)(size - segsize), uio);
					PIPE_LOCK(rpipe);
				}
				/*
				 * readers never know to read until count is updated.
				 */
				if (error == 0) {
					wpipe->pipe_buffer.in += size;
					if (wpipe->pipe_buffer.in >
					    wpipe->pipe_buffer.size) {
						if (wpipe->pipe_buffer.in !=
						    size - segsize +
						    wpipe->pipe_buffer.size) {
							panic("Expected "
							    "wraparound bad");
						}
						wpipe->pipe_buffer.in = (unsigned int)(size -
						    segsize);
					}

					wpipe->pipe_buffer.cnt += size;
					if (wpipe->pipe_buffer.cnt >
					    wpipe->pipe_buffer.size) {
						panic("Pipe buffer overflow");
					}
				}
				pipeio_unlock(wpipe);
			}
			if (error) {
				break;
			}
		} else {
			/*
			 * If the "read-side" has been blocked, wake it up now.
			 */
			if (wpipe->pipe_state & PIPE_WANTR) {
				wpipe->pipe_state &= ~PIPE_WANTR;
				wakeup(wpipe);
			}

			/*
			 * If read side wants to go away, we just issue a signal
			 * to ourselves.
			 */
			if ((wpipe->pipe_state & (PIPE_DRAIN | PIPE_EOF)) ||
			    (fileproc_get_vflags(fp) & FPV_DRAIN)) {
				error = EPIPE;
				break;
			}

			/*
			 * don't block on non-blocking I/O
			 * we'll do the pipeselwakeup on the way out
			 */
			if (fp->f_flag & FNONBLOCK) {
				error = EAGAIN;
				break;
			}

			/*
			 * We have no more space and have something to offer,
			 * wake up select/poll.
			 */
			pipeselwakeup(wpipe, wpipe);

			wpipe->pipe_state |= PIPE_WANTW;

			error = msleep(wpipe, PIPE_MTX(wpipe), PRIBIO | PCATCH, "pipewr", 0);

			if (error != 0) {
				break;
			}
		}
	}
	--wpipe->pipe_busy;

	if ((wpipe->pipe_busy == 0) && (wpipe->pipe_state & PIPE_WANT)) {
		wpipe->pipe_state &= ~(PIPE_WANT | PIPE_WANTR);
		wakeup(wpipe);
	}
	if (wpipe->pipe_buffer.cnt > 0) {
		/*
		 * If there are any characters in the buffer, we wake up
		 * the reader if it was blocked waiting for data.
		 */
		if (wpipe->pipe_state & PIPE_WANTR) {
			wpipe->pipe_state &= ~PIPE_WANTR;
			wakeup(wpipe);
		}
		/*
		 * wake up thread blocked in select/poll or post the notification
		 */
		pipeselwakeup(wpipe, wpipe);
	}

#if defined(XNU_TARGET_OS_OSX)
	/* Update modification, status change (# of bytes in pipe) times */
	pipe_touch(rpipe, PIPE_MTIME | PIPE_CTIME);
	pipe_touch(wpipe, PIPE_MTIME | PIPE_CTIME);
#endif
	PIPE_UNLOCK(rpipe);

	return error;
}

/*
 * we implement a very minimal set of ioctls for compatibility with sockets.
 */
/* ARGSUSED 3 */
static int
pipe_ioctl(struct fileproc *fp, u_long cmd, caddr_t data,
    __unused vfs_context_t ctx)
{
	struct pipe *mpipe = (struct pipe *)fp->f_data;
#if CONFIG_MACF
	int error;
#endif

	PIPE_LOCK(mpipe);

#if CONFIG_MACF
	error = mac_pipe_check_ioctl(kauth_cred_get(), mpipe, cmd);
	if (error) {
		PIPE_UNLOCK(mpipe);

		return error;
	}
#endif

	switch (cmd) {
	case FIONBIO:
		PIPE_UNLOCK(mpipe);
		return 0;

	case FIOASYNC:
		if (*(int *)data) {
			mpipe->pipe_state |= PIPE_ASYNC;
		} else {
			mpipe->pipe_state &= ~PIPE_ASYNC;
		}
		PIPE_UNLOCK(mpipe);
		return 0;

	case FIONREAD:
		*(int *)data = mpipe->pipe_buffer.cnt;
		PIPE_UNLOCK(mpipe);
		return 0;

	case TIOCSPGRP:
		mpipe->pipe_pgid = *(int *)data;

		PIPE_UNLOCK(mpipe);
		return 0;

	case TIOCGPGRP:
		*(int *)data = mpipe->pipe_pgid;

		PIPE_UNLOCK(mpipe);
		return 0;
	}
	PIPE_UNLOCK(mpipe);
	return ENOTTY;
}


static int
pipe_select(struct fileproc *fp, int which, void *wql, vfs_context_t ctx)
{
	struct pipe *rpipe = (struct pipe *)fp->f_data;
	struct pipe *wpipe;
	int    retnum = 0;

	if (rpipe == NULL || rpipe == (struct pipe *)-1) {
		return retnum;
	}

	PIPE_LOCK(rpipe);

	wpipe = rpipe->pipe_peer;


#if CONFIG_MACF
	/*
	 * XXX We should use a per thread credential here; minimally, the
	 * XXX process credential should have a persistent reference on it
	 * XXX before being passed in here.
	 */
	if (mac_pipe_check_select(vfs_context_ucred(ctx), rpipe, which)) {
		PIPE_UNLOCK(rpipe);
		return 0;
	}
#endif
	switch (which) {
	case FREAD:
		if ((rpipe->pipe_state & PIPE_DIRECTW) ||
		    (rpipe->pipe_buffer.cnt > 0) ||
		    (rpipe->pipe_state & (PIPE_DRAIN | PIPE_EOF)) ||
		    (fileproc_get_vflags(fp) & FPV_DRAIN)) {
			retnum = 1;
		} else {
			rpipe->pipe_state |= PIPE_SEL;
			selrecord(vfs_context_proc(ctx), &rpipe->pipe_sel, wql);
		}
		break;

	case FWRITE:
		if (wpipe) {
			wpipe->pipe_state |= PIPE_WSELECT;
		}
		if (wpipe == NULL || (wpipe->pipe_state & (PIPE_DRAIN | PIPE_EOF)) ||
		    (fileproc_get_vflags(fp) & FPV_DRAIN) ||
		    (((wpipe->pipe_state & PIPE_DIRECTW) == 0) &&
		    (MAX_PIPESIZE(wpipe) - wpipe->pipe_buffer.cnt) >= PIPE_BUF)) {
			retnum = 1;
		} else {
			wpipe->pipe_state |= PIPE_SEL;
			selrecord(vfs_context_proc(ctx), &wpipe->pipe_sel, wql);
		}
		break;
	case 0:
		rpipe->pipe_state |= PIPE_SEL;
		selrecord(vfs_context_proc(ctx), &rpipe->pipe_sel, wql);
		break;
	}
	PIPE_UNLOCK(rpipe);

	return retnum;
}


/* ARGSUSED 1 */
static int
pipe_close(struct fileglob *fg, __unused vfs_context_t ctx)
{
	struct pipe *cpipe;

	proc_fdlock_spin(vfs_context_proc(ctx));
	cpipe = (struct pipe *)fg->fg_data;
	fg->fg_data = NULL;
	proc_fdunlock(vfs_context_proc(ctx));
	if (cpipe) {
		pipeclose(cpipe);
	}

	return 0;
}

static void
pipe_free_kmem(struct pipe *cpipe)
{
	if (cpipe->pipe_buffer.buffer != NULL) {
		OSAddAtomic(-(cpipe->pipe_buffer.size), &amountpipekva);
		OSAddAtomic(-1, &amountpipes);
		kheap_free(KHEAP_DATA_BUFFERS, cpipe->pipe_buffer.buffer,
		    cpipe->pipe_buffer.size);
		cpipe->pipe_buffer.buffer = NULL;
		cpipe->pipe_buffer.size = 0;
	}
}

/*
 * shutdown the pipe
 */
static void
pipeclose(struct pipe *cpipe)
{
	struct pipe *ppipe;

	PIPE_LOCK(cpipe);

	/*
	 * If the other side is blocked, wake it up saying that
	 * we want to close it down.
	 */
	cpipe->pipe_state &= ~PIPE_DRAIN;
	cpipe->pipe_state |= PIPE_EOF;
	pipeselwakeup(cpipe, cpipe);

	while (cpipe->pipe_busy) {
		cpipe->pipe_state |= PIPE_WANT;

		wakeup(cpipe);
		msleep(cpipe, PIPE_MTX(cpipe), PRIBIO, "pipecl", 0);
	}

#if CONFIG_MACF
	/*
	 * Free the shared pipe label only after the two ends are disconnected.
	 */
	if (cpipe->pipe_label != NULL && cpipe->pipe_peer == NULL) {
		mac_pipe_label_destroy(cpipe);
	}
#endif

	/*
	 * Disconnect from peer
	 */
	if ((ppipe = cpipe->pipe_peer) != NULL) {
		ppipe->pipe_state &= ~(PIPE_DRAIN);
		ppipe->pipe_state |= PIPE_EOF;

		pipeselwakeup(ppipe, ppipe);
		wakeup(ppipe);

		KNOTE(&ppipe->pipe_sel.si_note, 1);

		ppipe->pipe_peer = NULL;
	}

	/*
	 * free resources
	 */

	PIPE_UNLOCK(cpipe);

	pipepair_destroy_pipe(PIPE_PAIR(cpipe), cpipe);
}

static int64_t
filt_pipelowwat(struct knote *kn, struct pipe *rpipe, int64_t def_lowwat)
{
	if ((kn->kn_sfflags & NOTE_LOWAT) == 0) {
		return def_lowwat;
	}
	if (rpipe->pipe_buffer.size && kn->kn_sdata > MAX_PIPESIZE(rpipe)) {
		return MAX_PIPESIZE(rpipe);
	}
	return MAX(kn->kn_sdata, def_lowwat);
}

static int
filt_pipe_draincommon(struct knote *kn, struct pipe *rpipe)
{
	struct pipe *wpipe = rpipe->pipe_peer;

	if ((rpipe->pipe_state & (PIPE_DRAIN | PIPE_EOF)) ||
	    (wpipe == NULL) || (wpipe->pipe_state & (PIPE_DRAIN | PIPE_EOF))) {
		kn->kn_flags |= EV_EOF;
		return 1;
	}

	return 0;
}

static int
filt_pipenotsup(struct knote *kn, long hint)
{
#pragma unused(hint)
	struct pipe *rpipe = kn->kn_hook;

	return filt_pipe_draincommon(kn, rpipe);
}

static int
filt_pipenotsuptouch(struct knote *kn, struct kevent_qos_s *kev)
{
	struct pipe *rpipe = kn->kn_hook;
	int res;

	PIPE_LOCK(rpipe);

	/* accept new kevent data (and save off lowat threshold and flag) */
	kn->kn_sfflags = kev->fflags;
	kn->kn_sdata = kev->data;

	/* determine if any event is now deemed fired */
	res = filt_pipe_draincommon(kn, rpipe);

	PIPE_UNLOCK(rpipe);

	return res;
}

static int
filt_pipenotsupprocess(struct knote *kn, struct kevent_qos_s *kev)
{
	struct pipe *rpipe = kn->kn_hook;
	int res;

	PIPE_LOCK(rpipe);
	res = filt_pipe_draincommon(kn, rpipe);
	if (res) {
		knote_fill_kevent(kn, kev, 0);
	}
	PIPE_UNLOCK(rpipe);

	return res;
}

/*ARGSUSED*/
static int
filt_piperead_common(struct knote *kn, struct kevent_qos_s *kev, struct pipe *rpipe)
{
	int64_t data = rpipe->pipe_buffer.cnt;
	int res = 0;

	if (filt_pipe_draincommon(kn, rpipe)) {
		res = 1;
	} else {
		res = data >= filt_pipelowwat(kn, rpipe, 1);
	}
	if (res && kev) {
		knote_fill_kevent(kn, kev, data);
	}
	return res;
}

static int
filt_piperead(struct knote *kn, long hint)
{
#pragma unused(hint)
	struct pipe *rpipe = kn->kn_hook;

	return filt_piperead_common(kn, NULL, rpipe);
}

static int
filt_pipereadtouch(struct knote *kn, struct kevent_qos_s *kev)
{
	struct pipe *rpipe = kn->kn_hook;
	int retval;

	PIPE_LOCK(rpipe);

	/* accept new inputs (and save the low water threshold and flag) */
	kn->kn_sdata = kev->data;
	kn->kn_sfflags = kev->fflags;

	/* identify if any events are now fired */
	retval = filt_piperead_common(kn, NULL, rpipe);

	PIPE_UNLOCK(rpipe);

	return retval;
}

static int
filt_pipereadprocess(struct knote *kn, struct kevent_qos_s *kev)
{
	struct pipe *rpipe = kn->kn_hook;
	int    retval;

	PIPE_LOCK(rpipe);
	retval = filt_piperead_common(kn, kev, rpipe);
	PIPE_UNLOCK(rpipe);

	return retval;
}

/*ARGSUSED*/
static int
filt_pipewrite_common(struct knote *kn, struct kevent_qos_s *kev, struct pipe *rpipe)
{
	int64_t data = 0;
	int res = 0;

	if (filt_pipe_draincommon(kn, rpipe)) {
		res = 1;
	} else {
		data = MAX_PIPESIZE(rpipe) - rpipe->pipe_buffer.cnt;
		res = data >= filt_pipelowwat(kn, rpipe, PIPE_BUF);
	}
	if (res && kev) {
		knote_fill_kevent(kn, kev, data);
	}
	return res;
}

/*ARGSUSED*/
static int
filt_pipewrite(struct knote *kn, long hint)
{
#pragma unused(hint)
	struct pipe *rpipe = kn->kn_hook;

	return filt_pipewrite_common(kn, NULL, rpipe);
}


static int
filt_pipewritetouch(struct knote *kn, struct kevent_qos_s *kev)
{
	struct pipe *rpipe = kn->kn_hook;
	int res;

	PIPE_LOCK(rpipe);

	/* accept new kevent data (and save off lowat threshold and flag) */
	kn->kn_sfflags = kev->fflags;
	kn->kn_sdata = kev->data;

	/* determine if any event is now deemed fired */
	res = filt_pipewrite_common(kn, NULL, rpipe);

	PIPE_UNLOCK(rpipe);

	return res;
}

static int
filt_pipewriteprocess(struct knote *kn, struct kevent_qos_s *kev)
{
	struct pipe *rpipe = kn->kn_hook;
	int res;

	PIPE_LOCK(rpipe);
	res = filt_pipewrite_common(kn, kev, rpipe);
	PIPE_UNLOCK(rpipe);

	return res;
}

/*ARGSUSED*/
static int
pipe_kqfilter(struct fileproc *fp, struct knote *kn,
    __unused struct kevent_qos_s *kev)
{
	struct pipe *cpipe = (struct pipe *)fp->f_data;
	struct pipe *rpipe = &PIPE_PAIR(cpipe)->pp_rpipe;
	int res;

	PIPE_LOCK(cpipe);
#if CONFIG_MACF
	/*
	 * XXX We should use a per thread credential here; minimally, the
	 * XXX process credential should have a persistent reference on it
	 * XXX before being passed in here.
	 */
	kauth_cred_t cred = vfs_context_ucred(vfs_context_current());
	if (mac_pipe_check_kqfilter(cred, kn, cpipe) != 0) {
		PIPE_UNLOCK(cpipe);
		knote_set_error(kn, EPERM);
		return 0;
	}
#endif

	/*
	 * FreeBSD will fail the attach with EPIPE if the peer pipe is detached,
	 * however, this isn't a programming error as the other side closing
	 * could race with the kevent registration.
	 *
	 * Attach should only fail for programming mistakes else it will break
	 * libdispatch.
	 *
	 * Like FreeBSD, have a "Neutered" filter that will not fire until
	 * the pipe dies if the wrong filter is attached to the wrong end.
	 *
	 * Knotes are always attached to the "rpipe".
	 */
	switch (kn->kn_filter) {
	case EVFILT_READ:
		if (fp->f_flag & FREAD) {
			kn->kn_filtid = EVFILTID_PIPE_R;
			res = filt_piperead_common(kn, NULL, rpipe);
		} else {
			kn->kn_filtid = EVFILTID_PIPE_N;
			res = filt_pipe_draincommon(kn, rpipe);
		}
		break;

	case EVFILT_WRITE:
		if (fp->f_flag & FWRITE) {
			kn->kn_filtid = EVFILTID_PIPE_W;
			res = filt_pipewrite_common(kn, NULL, rpipe);
		} else {
			kn->kn_filtid = EVFILTID_PIPE_N;
			res = filt_pipe_draincommon(kn, rpipe);
		}
		break;

	default:
		PIPE_UNLOCK(cpipe);
		knote_set_error(kn, EINVAL);
		return 0;
	}

	kn->kn_hook = rpipe;
	KNOTE_ATTACH(&rpipe->pipe_sel.si_note, kn);

	PIPE_UNLOCK(cpipe);
	return res;
}

static void
filt_pipedetach(struct knote *kn)
{
	struct pipe *cpipe = (struct pipe *)kn->kn_fp->f_data;
	struct pipe *rpipe = &PIPE_PAIR(cpipe)->pp_rpipe;

	PIPE_LOCK(cpipe);
	KNOTE_DETACH(&rpipe->pipe_sel.si_note, kn);
	PIPE_UNLOCK(cpipe);
}

int
fill_pipeinfo(struct pipe * cpipe, struct pipe_info * pinfo)
{
#if CONFIG_MACF
	int error;
#endif
	struct timespec now;
	struct vinfo_stat * ub;
	int pipe_size = 0;
	int pipe_count;

	if (cpipe == NULL) {
		return EBADF;
	}
	PIPE_LOCK(cpipe);

#if CONFIG_MACF
	error = mac_pipe_check_stat(kauth_cred_get(), cpipe);
	if (error) {
		PIPE_UNLOCK(cpipe);
		return error;
	}
#endif
	if (cpipe->pipe_buffer.buffer == 0) {
		/*
		 * must be stat'ing the write fd
		 */
		if (cpipe->pipe_peer) {
			/*
			 * the peer still exists, use it's info
			 */
			pipe_size  = MAX_PIPESIZE(cpipe->pipe_peer);
			pipe_count = cpipe->pipe_peer->pipe_buffer.cnt;
		} else {
			pipe_count = 0;
		}
	} else {
		pipe_size  = MAX_PIPESIZE(cpipe);
		pipe_count = cpipe->pipe_buffer.cnt;
	}
	/*
	 * since peer's buffer is setup ouside of lock
	 * we might catch it in transient state
	 */
	if (pipe_size == 0) {
		pipe_size  = PIPE_SIZE;
	}

	ub = &pinfo->pipe_stat;

	bzero(ub, sizeof(*ub));
	ub->vst_mode = S_IFIFO | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
	ub->vst_blksize = pipe_size;
	ub->vst_size = pipe_count;
	if (ub->vst_blksize != 0) {
		ub->vst_blocks = (ub->vst_size + ub->vst_blksize - 1) / ub->vst_blksize;
	}
	ub->vst_nlink = 1;

	ub->vst_uid = kauth_getuid();
	ub->vst_gid = kauth_getgid();

	nanotime(&now);
	ub->vst_atime  = now.tv_sec;
	ub->vst_atimensec = now.tv_nsec;

	ub->vst_mtime  = now.tv_sec;
	ub->vst_mtimensec = now.tv_nsec;

	ub->vst_ctime  = now.tv_sec;
	ub->vst_ctimensec = now.tv_nsec;

	/*
	 * Left as 0: st_dev, st_ino, st_nlink, st_rdev, st_flags, st_gen, st_uid, st_gid.
	 * XXX (st_dev, st_ino) should be unique.
	 */

	pinfo->pipe_handle = (uint64_t)VM_KERNEL_ADDRHASH((uintptr_t)cpipe);
	pinfo->pipe_peerhandle = (uint64_t)VM_KERNEL_ADDRHASH((uintptr_t)(cpipe->pipe_peer));
	pinfo->pipe_status = cpipe->pipe_state;

	PIPE_UNLOCK(cpipe);

	return 0;
}


static int
pipe_drain(struct fileproc *fp, __unused vfs_context_t ctx)
{
	/* Note: fdlock already held */
	struct pipe *ppipe, *cpipe = (struct pipe *)(fp->fp_glob->fg_data);
	boolean_t drain_pipe = FALSE;

	/* Check if the pipe is going away */
	lck_mtx_lock_spin(&fp->fp_glob->fg_lock);
	if (os_ref_get_count_raw(&fp->fp_glob->fg_count) == 1) {
		drain_pipe = TRUE;
	}
	lck_mtx_unlock(&fp->fp_glob->fg_lock);

	if (cpipe) {
		PIPE_LOCK(cpipe);

		if (drain_pipe) {
			cpipe->pipe_state |= PIPE_DRAIN;
			cpipe->pipe_state &= ~(PIPE_WANTR | PIPE_WANTW);
		}
		wakeup(cpipe);

		/* Must wake up peer: a writer sleeps on the read side */
		if ((ppipe = cpipe->pipe_peer)) {
			if (drain_pipe) {
				ppipe->pipe_state |= PIPE_DRAIN;
				ppipe->pipe_state &= ~(PIPE_WANTR | PIPE_WANTW);
			}
			wakeup(ppipe);
		}

		PIPE_UNLOCK(cpipe);
		return 0;
	}

	return 1;
}
